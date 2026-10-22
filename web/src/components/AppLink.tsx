import { forwardRef, type AnchorHTMLAttributes } from "react";
import { Link } from "react-router";

/** Routes internal hrefs through the client-side router; external links stay plain anchors. */
export const AppLink = forwardRef<HTMLAnchorElement, AnchorHTMLAttributes<HTMLAnchorElement>>(function AppLink({ href = "", ...rest }, ref) {
  const external = /^(https?:|mailto:|tel:)/.test(href) || href.startsWith("/api/") || rest.target === "_blank" || rest.download !== undefined;
  if (external) return <a ref={ref} href={href} {...rest} />;
  return <Link ref={ref} to={href} {...rest} />;
});
