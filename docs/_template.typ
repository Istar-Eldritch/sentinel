// Sentinel Document Template
//
// Usage:
//   #import "_template.typ": *
//   #show: doc-setup.with(
//     title: "DOCUMENT TITLE",
//     subtitle: "OPTIONAL SUBTITLE",
//     section: "2602180855",
//     status: "DRAFT",
//     date: "FEB 2026",
//     updated: "2026-02-18",
//   )
//
// Compile:
//   typst compile docs/your_doc.typ
//
// Requires: Berkeley Mono font (monospaced typewriter style)

// =============================================================================
// DOCUMENT SETUP (use with #show: doc-setup.with(...))
// =============================================================================

#let doc-setup(
  title: "",
  subtitle: none,
  section: none,
  status: none,
  org: "SENTINEL",
  date: none,
  updated: none,
  revision: none,
  tagline: none,
  body
) = {
  set document(title: title, author: "Sentinel")

  set page(
    paper: "a4",
    margin: (x: 2.5cm, y: 2cm),
    header: context {
      set text(size: 10pt, weight: "regular")
      grid(
        columns: (1fr, 1fr),
        align: (left, right),
        [#upper(org)],
        if section != none {
          [#section \ #upper(date)]
        } else {
          [#upper(date)]
        }
      )
    },
    footer: context {
      set text(size: 10pt, weight: "regular")
      if counter(page).get().first() > 1 {
        grid(
          columns: (1fr, 1fr, 1fr),
          align: (left, center, right),
          [SENTINEL],
          if tagline != none { text(style: "italic")[#tagline] },
          [Page #counter(page).display()]
        )
      }
    },
  )

  set text(font: "Berkeley Mono", size: 10pt, weight: "regular")
  show raw: set text(font: "Berkeley Mono", weight: "regular")
  set heading(numbering: none)

  // Title box (centered, framed)
  if title != "" {
    v(2em)
    align(center)[
      #box(
        stroke: 1pt + black,
        inset: (x: 2em, y: 0.8em),
        [
          #text(size: 10pt, weight: "bold")[#upper(title)]
          #if subtitle != none [
            \ #text(size: 10pt, weight: "bold")[#upper(subtitle)]
          ]
        ]
      )
    ]
    v(1em)
    
    // Status, updated, and revision info below title (stacked on left)
    if status != none or updated != none or revision != none {
      align(left)[
        #if status != none [
          *STATUS:* #upper(status) \
        ]
        #if updated != none [
          *UPDATED:* #updated \
        ]
        #if revision != none [
          *REVISION:* #revision
        ]
      ]
    }
    v(2em)
  }

  show heading.where(level: 1): it => {
    set text(size: 10pt, weight: "regular")
    v(1.5em)
    block(breakable: false, below: 0.5em)[
      #upper(it.body)
      #v(-0.5em)
      #line(length: 100%, stroke: 0.5pt + black)
    ]
  }

  show heading.where(level: 2): it => {
    set text(size: 10pt, weight: "regular")
    v(1em)
    block(breakable: false, below: 0.8em, upper(it.body))
  }

  show heading.where(level: 3): it => {
    set text(size: 10pt, weight: "regular")
    v(0.8em)
    block(breakable: false, below: 0.2em, it.body)
  }

  show raw.where(block: true): it => {
    set text(size: 9pt, font: "Berkeley Mono", weight: "regular")
    block(breakable: false, inset: (left: 2em), it)
  }

  show raw.where(block: false): it => {
    set text(font: "Berkeley Mono", weight: "regular")
    it
  }

  set par(leading: 0.65em, spacing: 1em)

  body
}

// =============================================================================
// HORIZONTAL RULE
// =============================================================================

#let hr() = {
  v(0.5em)
  line(length: 100%, stroke: 0.5pt + black)
  v(0.5em)
}

// =============================================================================
// CALLOUT BOXES
// =============================================================================

#let note-box(content) = {
  v(1em)
  block(
    breakable: false,
    width: 100%,
    stroke: 0.5pt + black,
    inset: 1em,
    content
  )
  v(1em)
}

#let printing-note(content) = {
  v(1em)
  hr()
  text(style: "italic")[#content]
  hr()
  v(1em)
}

// =============================================================================
// REFERENCE FORMATTING
// =============================================================================

#let page-ref(page-number) = {
  [page number #page-number]
}

#let field-list(..fields) = {
  for field in fields.pos() {
    grid(
      columns: (auto, 1fr),
      column-gutter: 1em,
      [#field.at(0)], [#field.at(1)]
    )
  }
}
