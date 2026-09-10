# RedOps branding

<img src="../redops/web/static/redops-mark.png" alt="RedOps mark" width="160" height="160">

The RedOps mark is a crimson geometric R with an open counter and a diagonal
leg. Use the mark alone in the application, with no adjacent wordmark or tagline.
The project name remains **RedOps**, without a release number.

## Asset and integration

The master asset is [redops-mark.png](../redops/web/static/redops-mark.png), a
1254 × 1254 RGBA PNG with a transparent background and built-in clear space.
The color direction is crimson (`#E4475C`); the generated image contains slight
color variation. Preserve its square proportions and transparency.

- The dashboard sidebar and centered login screen use the mark alone. The browser
  icon and touch icon use the same local asset.
- HTML assessment and paired benchmark reports embed the PNG as a data URI.
  PDF assessments embed it in the page header. Exports remain self-contained.
- The README uses the repository asset. The wheel and source distribution
  include it, and `redops doctor` checks that it is present.

The navigation logo link has the accessible name `RedOps home`; its image has empty
alternative text. The standalone login mark uses `alt="RedOps"`. These accessible
names do not add a visible wordmark.
See the [desktop dashboard](images/dashboard-desktop.png) and
[mobile dashboard](images/dashboard-mobile.png), plus the
[desktop login](images/login-desktop.png) and [mobile login](images/login-mobile.png),
for examples. Screenshots contain synthetic fixtures or an empty sign-in form.

## Interface direction

The application uses solid charcoal surfaces, fine dividers, restrained crimson
accents, and a persistent sidebar. It has no background lighting, gradients, or
blur. The login card remains centered horizontally and vertically, including its
logo, heading, field, and button. Assessment pages use short titles; provenance
and interpretation live in expandable details. Severity and review charts show
actual assessment totals.

The main references are the Smartnet cybersecurity dashboard series by Firoz
Hossain and collaborators on Behance:

- [Dashboard overview](https://www.behance.net/gallery/185119011/Smartnet-CyberSecurity-Dashboard-Design):
  approximately **1.2K appreciations** when checked on September 9, 2026.
- [Data security view](https://www.behance.net/gallery/185607413/Smartnet-CyberSecurity-Dashboard-Design):
  approximately **1.1K appreciations** on the same date.

These informed the sidebar hierarchy, compact metrics, and structured data
panels. RedOps uses its own CSS, icons, and assessment data. Reference artwork is
not bundled or loaded by the application. System fonts and local assets keep
the interface offline; reduced motion and forced colors are supported.

## Generation record

Created using Codex's built-in image generation tool. The PNG is the generated
original, not a vector tracing. Final prompt:

> Use case: logo-brand. Create one final modern minimalist logo symbol for RedOps,
> a professional cybersecurity assessment software project. Asset: a compact icon
> to sit beside the typeset name RedOps in a website header and to serve as its
> browser favicon. Design a distinctive uppercase R monogram from bold precise
> geometric shapes, with a clean open counter, a decisive diagonal lower leg, and
> subtle 45-degree cuts. It must read immediately as R, have a strong balanced
> silhouette, and remain legible at 24–40 pixels. Flat vector-like rendering, crisp
> edges, uniform intentional geometry, one solid vivid crimson color #E4475C.
> Genuine transparent background with an alpha channel, including the counter of
> the R; no background rectangle. Square canvas, one centered symbol occupying
> about 80 percent of the canvas with equal clean padding. No words, lettering
> other than the R monogram, tagline, version number, gradients, shadows,
> textures, 3D effects, mockups, border, shield, padlock, skull, crosshair, or
> decorative circuitry. Deliver just the final transparent logo symbol, not a
> presentation board or multiple options.
