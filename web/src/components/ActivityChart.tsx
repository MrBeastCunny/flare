import { useEffect, useState } from "react";
import * as echarts from "echarts/core";
import { BarChart, LineChart } from "echarts/charts";
import { GridComponent, TooltipComponent, BrushComponent, ToolboxComponent } from "echarts/components";
import { CanvasRenderer } from "echarts/renderers";
import { TimeseriesChart } from "@cloudflare/kumo";
import type { DayCount } from "../lib/types";

echarts.use([BarChart, LineChart, GridComponent, TooltipComponent, BrushComponent, ToolboxComponent, CanvasRenderer]);

function useDarkMode() {
  const [dark, setDark] = useState(() => document.documentElement.getAttribute("data-mode") === "dark");
  useEffect(() => {
    const obs = new MutationObserver(() => setDark(document.documentElement.getAttribute("data-mode") === "dark"));
    obs.observe(document.documentElement, { attributes: true, attributeFilter: ["data-mode"] });
    return () => obs.disconnect();
  }, []);
  return dark;
}

const CRIMSON = "#c8102e";

/** Daily change volume (from the audit log) as a flat bar chart. */
export function ActivityChart({ data, height = 220, name = "Changes", loading }: { data: DayCount[]; height?: number; name?: string; loading?: boolean }) {
  const dark = useDarkMode();
  return (
    <TimeseriesChart
      echarts={echarts}
      isDarkMode={dark}
      type="bar"
      height={height}
      loading={loading}
      gradient={false}
      yAxisMinInterval={1}
      xAxisTickFormat={(v) => new Date(v).toLocaleDateString(undefined, { month: "short", day: "numeric" })}
      tooltipTimestampFormat={(v) => new Date(v).toLocaleDateString(undefined, { weekday: "short", month: "short", day: "numeric" })}
      data={[{ name, color: CRIMSON, data: data.map((d) => [new Date(d.day).getTime(), d.count]) }]}
      ariaDescription={`${name} per day over the last ${data.length} days`}
    />
  );
}
