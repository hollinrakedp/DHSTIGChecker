<#
Rule Title: Domain controllers must have a PKI server certificate.
Severity: medium
Vuln ID: V-224991
STIG ID: WN16-DC-000280

Discussion:
Domain controllers are part of the chain of trust for PKI authentications. Without the appropriate certificate, the authenticity of the domain controller cannot be verified. Domain controllers must have a server certificate to establish authenticity as part of PKI authentications in the domain.


Check Content:
This applies to domain controllers. It is NA for other systems.

Run "MMC".

Select "Add/Remove Snap-in" from the "File" menu.

Select "Certificates" in the left pane and click the "Add >" button.

Select "Computer Account" and click "Next".

Select the appropriate option for "Select the computer you want this snap-in to manage" and click "Finish".

Click "OK".

Select and expand the Certificates (Local Computer) entry in the left pane.

Select and expand the Personal entry in the left pane.

Select the Certificates entry in the left pane.

If no certificate for the domain controller exists in the right pane, this is a finding.

#>
return 'Not Reviewed'
