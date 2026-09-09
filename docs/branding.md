# RedOps branding

<img src="../redops/web/static/redops-mark.png" alt="RedOps mark" width="160" height="160">

The RedOps mark is a crimson geometric R with an open counter and a diagonal
leg. Use the name **RedOps** alongside the mark, without a release number.

## Asset and integration

The master asset is [redops-mark.png](../redops/web/static/redops-mark.png), a
1254 × 1254 RGBA PNG with a transparent background and built-in clear space.
The color direction is crimson (`#E4475C`); the generated image contains slight
color variation. Preserve its square proportions and transparency.

- The dashboard header pairs the mark with the text wordmark. The login screen,
  browser icon, and touch icon use the same local asset.
- HTML assessment and paired benchmark reports embed the PNG as a data URI.
  PDF assessments embed it in the page header. Exports remain self-contained.
- The README uses the repository asset. The wheel and source distribution
  include it, and `redops doctor` checks that it is present.

Decorative marks beside text have empty alternative text so screen readers
announce the name once. Use `alt="RedOps"` when the image is the only label.
See the [desktop dashboard](images/dashboard-desktop.png) and
[mobile dashboard](images/dashboard-mobile.png), plus the
[desktop login](images/login-desktop.png) and [mobile login](images/login-mobile.png),
for examples. Screenshots contain synthetic fixtures or an empty sign-in form.

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
