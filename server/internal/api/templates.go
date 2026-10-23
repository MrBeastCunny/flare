package api

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/flare-dns/flare/internal/db"
	"github.com/flare-dns/flare/internal/dnsutil"
	"github.com/flare-dns/flare/internal/pdns"
	"github.com/flare-dns/flare/internal/store"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// Zone templates hold relative record names ("@", "www", "_dmarc") so they can be applied to any zone.

type templateInput struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Records     []store.TemplateRecord `json:"records"`
}

// validateTemplate checks every record against a placeholder zone so templates fail early.
func validateTemplate(in *templateInput) error {
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" || len(in.Name) > 100 {
		return errField("name", "Enter a template name")
	}
	if len(in.Records) > 1000 {
		return errField("records", "A template can contain at most 1000 records")
	}
	const probe = "template.invalid."
	for i := range in.Records {
		rec := &in.Records[i]
		rec.Type = strings.ToUpper(strings.TrimSpace(rec.Type))
		rec.Name = strings.TrimSpace(rec.Name)
		if rec.Name == "" {
			rec.Name = "@"
		}
		if !dnsutil.IsSupportedType(rec.Type) || rec.Type == "SOA" {
			return errField(fmt.Sprintf("records.%d.type", i), "Unsupported record type "+rec.Type)
		}
		if strings.HasSuffix(rec.Name, ".") {
			return errField(fmt.Sprintf("records.%d.name", i), "Use names relative to the zone, such as @ or www")
		}
		if rec.Type == "NS" && rec.Name == "@" {
			return errField(fmt.Sprintf("records.%d.name", i), "Apex NS records come from the zone's nameserver set and cannot be part of a template")
		}
		fq, err := dnsutil.RecordName(rec.Name, probe)
		if err != nil {
			return errField(fmt.Sprintf("records.%d.name", i), err.Error())
		}
		if rec.TTL <= 0 {
			rec.TTL = 3600
		}
		if _, err := dnsutil.NormalizeContent(probe, fq, rec.Type, rec.TTL, dnsutil.ExpandRelativeTargets(probe, rec.Type, rec.Content)); err != nil {
			return errField(fmt.Sprintf("records.%d.content", i), fmt.Sprintf("%s %s: %s", rec.Type, rec.Name, err.Error()))
		}
	}
	return nil
}

func (a *App) handleListTemplates(w http.ResponseWriter, r *http.Request) {
	org := orgFrom(r.Context())
	list, err := a.Store.ListTemplates(r.Context(), &org.ID)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	writeJSON(w, 200, list)
}

func (a *App) loadOrgTemplate(r *http.Request, writable bool) (*store.ZoneTemplate, error) {
	org := orgFrom(r.Context())
	id, err := uuid.Parse(chi.URLParam(r, "templateID"))
	if err != nil {
		return nil, errNotFound("Template")
	}
	t, err := a.Store.TemplateForOrg(r.Context(), &org.ID, id)
	if err != nil {
		return nil, err
	}
	if writable && t.OrgID == nil {
		return nil, errForbidden("Instance templates are managed by instance administrators.")
	}
	return t, nil
}

func (a *App) saveTemplate(w http.ResponseWriter, r *http.Request, orgID *uuid.UUID, existing *store.ZoneTemplate) {
	var in templateInput
	if err := decode(r, &in); err != nil {
		a.fail(w, r, err)
		return
	}
	if err := validateTemplate(&in); err != nil {
		a.fail(w, r, err)
		return
	}
	t := store.ZoneTemplate{OrgID: orgID, Name: in.Name, Description: strings.TrimSpace(in.Description), Records: in.Records}
	if act := actorFrom(r.Context()); act.Type == "user" {
		t.CreatedBy = &act.User.ID
	}
	action, status := "template.create", 201
	if existing != nil {
		t.ID = existing.ID
		action, status = "template.update", 200
	}
	saved, err := a.Store.SaveTemplate(r.Context(), t)
	if db.IsUniqueViolation(err) {
		a.fail(w, r, errField("name", "A template with this name already exists"))
		return
	}
	if err != nil {
		a.fail(w, r, err)
		return
	}
	a.audit(r, auditEvent{OrgID: orgID, Action: action, ResourceType: "template", ResourceID: saved.ID.String(), ResourceName: saved.Name,
		Metadata: map[string]any{"records": len(saved.Records), "scope": map[bool]string{true: "instance", false: "organization"}[orgID == nil]}})
	writeJSON(w, status, saved)
}

func (a *App) handleCreateTemplate(w http.ResponseWriter, r *http.Request) {
	org := orgFrom(r.Context())
	a.saveTemplate(w, r, &org.ID, nil)
}

func (a *App) handleUpdateTemplate(w http.ResponseWriter, r *http.Request) {
	t, err := a.loadOrgTemplate(r, true)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	a.saveTemplate(w, r, t.OrgID, t)
}

func (a *App) handleDeleteTemplate(w http.ResponseWriter, r *http.Request) {
	t, err := a.loadOrgTemplate(r, true)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if err := a.Store.DeleteTemplate(r.Context(), t.ID); err != nil {
		a.fail(w, r, err)
		return
	}
	a.audit(r, auditEvent{Action: "template.delete", ResourceType: "template", ResourceID: t.ID.String(), ResourceName: t.Name})
	writeJSON(w, 200, map[string]any{"ok": true})
}

// handleTemplateFromZone captures a zone's current records (except SOA and apex NS) as a template.
func (a *App) handleTemplateFromZone(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	z := zoneFrom(ctx)
	org := orgFrom(ctx)
	var in struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if err := decode(r, &in); err != nil {
		a.fail(w, r, err)
		return
	}
	c, err := a.PDNSForZone(ctx, z)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	pz, err := c.GetZone(ctx, z.Name, true)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	recs := []store.TemplateRecord{}
	for _, s := range pz.RRSets {
		if s.Type == "SOA" || (s.Type == "NS" && s.Name == z.Name) || s.Type == "DNSKEY" || s.Type == "RRSIG" {
			continue
		}
		rel := "@"
		if s.Name != z.Name {
			rel = strings.TrimSuffix(s.Name, "."+z.Name)
		}
		for _, rec := range s.Records {
			content := rec.Content
			// Make in-zone targets relative so the template works for other domains.
			if strings.HasSuffix(content, "."+z.Name) && (s.Type == "CNAME" || s.Type == "MX" || s.Type == "SRV" || s.Type == "NS" || s.Type == "ALIAS") {
				content = strings.TrimSuffix(content, "."+z.Name)
			} else if strings.HasSuffix(content, " "+z.Name) {
				content = strings.TrimSuffix(content, z.Name) + "@"
			}
			recs = append(recs, store.TemplateRecord{Name: rel, Type: s.Type, TTL: s.TTL, Content: content})
		}
	}
	tin := templateInput{Name: orStr(in.Name, "Copy of "+strings.TrimSuffix(z.Name, ".")), Description: in.Description, Records: recs}
	if strings.TrimSpace(tin.Name) == "" {
		a.fail(w, r, errField("name", "Enter a template name"))
		return
	}
	t := store.ZoneTemplate{OrgID: &org.ID, Name: strings.TrimSpace(tin.Name), Description: tin.Description, Records: recs}
	if act := actorFrom(ctx); act.Type == "user" {
		t.CreatedBy = &act.User.ID
	}
	saved, err := a.Store.SaveTemplate(ctx, t)
	if db.IsUniqueViolation(err) {
		a.fail(w, r, errField("name", "A template with this name already exists"))
		return
	}
	if err != nil {
		a.fail(w, r, err)
		return
	}
	a.audit(r, auditEvent{Action: "template.create", ResourceType: "template", ResourceID: saved.ID.String(), ResourceName: saved.Name,
		Metadata: map[string]any{"from_zone": z.Name, "records": len(recs)}})
	writeJSON(w, 201, saved)
}

// handleApplyTemplate merges or replaces a zone's records with a template.
func (a *App) handleApplyTemplate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	z := zoneFrom(ctx)
	org := orgFrom(ctx)
	var in struct {
		TemplateID uuid.UUID `json:"template_id"`
		Mode       string    `json:"mode"`
	}
	if err := decode(r, &in); err != nil {
		a.fail(w, r, err)
		return
	}
	if z.Kind == "Slave" || z.Kind == "Consumer" {
		a.fail(w, r, errConflict("Templates cannot be applied to secondary zones."))
		return
	}
	t, err := a.Store.TemplateForOrg(ctx, &org.ID, in.TemplateID)
	if errors.Is(err, db.ErrNotFound) {
		a.fail(w, r, errField("template_id", "Template not found"))
		return
	}
	if err != nil {
		a.fail(w, r, err)
		return
	}
	recs := make([]dnsutil.ParsedRR, 0, len(t.Records))
	for _, rec := range t.Records {
		recs = append(recs, dnsutil.ParsedRR{Name: rec.Name, Type: rec.Type, TTL: rec.TTL, Content: dnsutil.ExpandRelativeTargets(z.Name, rec.Type, rec.Content)})
	}
	sets, err := a.buildImportRRSets(z.Name, recs, orInt(a.Settings(ctx).DefaultTTL, 3600), true)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	unlock := lockZone(z.ID)
	defer unlock()
	c, err := a.PDNSForZone(ctx, z)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	pz, err := c.GetZone(ctx, z.Name, true)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	patches, added := mergeRRSets(pz, sets, in.Mode == "replace", z.Name)
	if len(patches) > 0 {
		if err := c.PatchRRSets(ctx, z.Name, patches); err != nil {
			a.fail(w, r, err)
			return
		}
	}
	a.audit(r, auditEvent{Action: "zone.template_apply", ResourceType: "zone", ResourceID: z.ID.String(), ResourceName: z.Name,
		Metadata: map[string]any{"template": t.Name, "mode": orStr(in.Mode, "merge"), "added": added}})
	writeJSON(w, 200, map[string]any{"added": added})
}

// mergeRRSets computes the patch set for an import or template application.
func mergeRRSets(pz *pdns.Zone, sets []pdns.RRSet, replace bool, zone string) ([]pdns.RRSet, int) {
	added := 0
	var patches []pdns.RRSet
	for _, s := range sets {
		// The SOA and apex NS records belong to the zone's settings and nameserver set, not to imported data.
		if s.Type == "SOA" || isApexNS(s.Name, s.Type, zone) {
			continue
		}
		existing := findRRSet(pz.RRSets, s.Name, s.Type)
		if !replace && existing != nil {
			merged := pdns.RRSet{Name: s.Name, Type: s.Type, TTL: s.TTL, ChangeType: "REPLACE", Records: existing.Records, Comments: existing.Comments}
			for _, rec := range s.Records {
				dup := false
				for _, e := range existing.Records {
					dup = dup || e.Content == rec.Content
				}
				if !dup {
					merged.Records = append(merged.Records, rec)
					added++
				}
			}
			patches = append(patches, merged)
		} else {
			added += len(s.Records)
			patches = append(patches, s)
		}
	}
	if replace {
		keep := map[string]bool{}
		for _, s := range sets {
			keep[s.Name+"|"+s.Type] = true
		}
		for _, e := range pz.RRSets {
			if e.Type == "SOA" || (e.Type == "NS" && e.Name == zone) || e.Type == "DNSKEY" || e.Type == "RRSIG" || keep[e.Name+"|"+e.Type] {
				continue
			}
			patches = append(patches, pdns.RRSet{Name: e.Name, Type: e.Type, ChangeType: "DELETE", Records: []pdns.Record{}, Comments: []pdns.Comment{}})
		}
	}
	return patches, added
}

// ---- Instance templates (administrators) ----

func (a *App) handleAdminTemplates(w http.ResponseWriter, r *http.Request) {
	list, err := a.Store.ListTemplates(r.Context(), nil)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	writeJSON(w, 200, list)
}

func (a *App) handleAdminCreateTemplate(w http.ResponseWriter, r *http.Request) {
	a.saveTemplate(w, r, nil, nil)
}

func (a *App) loadInstanceTemplate(r *http.Request) (*store.ZoneTemplate, error) {
	id, err := uuid.Parse(chi.URLParam(r, "templateID"))
	if err != nil {
		return nil, errNotFound("Template")
	}
	t, err := a.Store.TemplateForOrg(r.Context(), nil, id)
	if err != nil {
		return nil, err
	}
	return t, nil
}

func (a *App) handleAdminUpdateTemplate(w http.ResponseWriter, r *http.Request) {
	t, err := a.loadInstanceTemplate(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	a.saveTemplate(w, r, nil, t)
}

func (a *App) handleAdminDeleteTemplate(w http.ResponseWriter, r *http.Request) {
	t, err := a.loadInstanceTemplate(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if err := a.Store.DeleteTemplate(r.Context(), t.ID); err != nil {
		a.fail(w, r, err)
		return
	}
	a.audit(r, auditEvent{Action: "template.delete", ResourceType: "template", ResourceID: t.ID.String(), ResourceName: t.Name})
	writeJSON(w, 200, map[string]any{"ok": true})
}
