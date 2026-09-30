---
name: Detection gap or false positive
about: A skill was flagged that should not be, or passed when it should not have
labels: detection
---

**Kind**
- [ ] False positive (a benign skill was warned or blocked)
- [ ] Missed detection (a risky skill passed)

**The skill**
A link to a public skill, or the smallest skill that reproduces it. For missed detections, use reserved domains (`example.com`, `.test`, `.invalid`) and no live credentials. If the report itself would help attackers, email the address in SECURITY.md instead.

**What skill-scanner reported**
`skill-scanner scan <path> --format json` output, or the relevant finding lines.

**What you expected, and why**
