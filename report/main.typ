#import "resources/format.typ": project

#let versions = (
  (
    "v1.0",
    "24.02.2025",
    "Creation of the document outline."
  ),
  (
    "v1.1",
    "24.02.2025",
    "Automatically generated document version table."
  ),
  (
    "v1.2",
    "07.04.2025",
    "Added description of the key generator for control term."
  )
)

#show: project.with(
  title: "Security of Computer Systems",
  subtitle: "",
  authors: (
    "Jakub Jędrzejczyk, 188752",
  ),
  school-logo: [],
  company-logo: [],
  mentors: (),
  jury: (),
  branch: none,
  academic-year: none,
  polish: false,
  footer-text: "",
  supertitle: "Project Report",
  subject: [],
  versions: versions
)

#include "chapters/abstract.typ"

#include "chapters/keygen.typ"

#include "chapters/signer.typ"

#include "chapters/summary.typ"