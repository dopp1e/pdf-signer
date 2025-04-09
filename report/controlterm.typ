#import "resources/format.typ": project

#let versions = (
  (
    "v1.0",
    "07.04.2025",
    "Creation of the document."
  ),
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
  supertitle: "Control Term",
  subject: [],
  versions: versions
)

= GitHub Repository

#show link: set text(blue)

The GitHub repository containing the project's code can be found #link("https://github.com/jakub-jedrzejczyk/pdf-signer")[here].