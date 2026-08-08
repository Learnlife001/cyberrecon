import type { MetadataRoute } from "next";

export default function manifest(): MetadataRoute.Manifest {
  return {
    name: "CyberRecon Threat Intelligence Console",
    short_name: "CyberRecon",
    description: "Authorized external attack-surface reconnaissance console.",
    start_url: "/",
    display: "standalone",
    background_color: "#070a12",
    theme_color: "#070a12",
    icons: [{ src: "/icon.svg", sizes: "any", type: "image/svg+xml" }],
  };
}
