# Third-party assets

`Assets/ServiceIcons/*.svg` are Microsoft product icons (Entra ID, Exchange,
SharePoint, Teams, Defender, Intune, Forms, Power BI, Purview, Office), used
here solely to visually identify which Microsoft 365 service a finding
belongs to. They are trademarks/icons of Microsoft Corporation, included for
identification purposes only — this project is not affiliated with, endorsed
by, or sponsored by Microsoft. If you fork or redistribute this project and
want to avoid any dependency on Microsoft's icon set, swap that folder's
contents for your own icons; `generate_pdf.py` and
`Private/Write-EntrAuditHtmlReport.ps1` both fall back to a plain gray
placeholder icon for any service prefix with no matching file.
