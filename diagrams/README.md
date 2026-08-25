# Figures

`*.mmd` are the mermaid sources as they appear in [`../ARTICLE.md`](../ARTICLE.md),
using `flowchart LR`. GitHub renders those inline, and a wide page suits them.

`medium/` holds `flowchart TD` variants and rendered PNGs, for publishing to a
narrow single column where the horizontal versions scale down to illegibility.
A nine-to-one aspect ratio becomes 77 pixels tall in a 700 pixel column.

Diagram 1 is not merely rotated: the chain was shortened and the dotted edge
reversed to point forward into the threat report rather than backward out of it,
which is both a better layout and a clearer statement.

Rendered with:

    npx @mermaid-js/mermaid-cli -i FILE.mmd -o FILE.png -b white -w 1400
