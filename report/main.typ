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

