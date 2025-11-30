<#
.SYNOPSIS
Automates privileged account and ACL remediation in isolated Active Directory environments.

.DESCRIPTION
Invoke-ControlDisposition detects and remediates privileged users, groups, and
sensitive container permissions across isolated or recovery domain controllers.

By default, the function operates in simulation mode (WhatIf=True).  
Use the -Execute parameter to apply all remediation actions.

.PARAMETER IsolatedDCList
Specifies a collection of domain controller objects containing metadata such as
FQDN, Domain name, Domain type, SIDs, and Naming Contexts.  
Used to establish per-domain context and target remediation operations.

.PARAMETER Execute
Applies all remediation actions. When omitted, actions are simulated (WhatIf=True).

.EXAMPLE
# Simulate all remediation actions
Invoke-ControlDisposition -IsolatedDCList $dcs

.EXAMPLE
# Apply all remediation changes
Invoke-ControlDisposition -IsolatedDCList $dcs -Execute

.OUTPUTS
PSCustomObject  
Returns a structured summary including domains processed, privileged users,
groups modified, ACL resets, and remediation statistics.

.NOTES
Author: NightCityShogun  
Version: 1.0  
Requires: Administrative privileges in isolated/recovery Active Directory environments.  
Excludes RID 500 and break-glass accounts by design.  
© 2025 NightCityShogun. All rights reserved.
#>

function Invoke-ControlDisposition {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [ValidateNotNullOrEmpty()]
        [psobject[]]$IsolatedDCList,
        [Parameter()]
        [switch]$Execute
    )
    begin {

        # Static BaselineArray
        $script:BaselineArray = @(
            @{
                DomainType = "Forest Root"
                DomainSid = "{DomainSid}"
                ForestSid = "{ForestSid}"
                SDDL = @{
                    DomainControllers = @{
                        InheritanceBlocked = $false
                        SDDL = "D:AI(A;;LCRPLORC;;;ED)(A;;LCRPLORC;;;AU)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCLCSWRPWPLOCRRCWDWO;;;{DomainSid}-512)(OA;CIIOID;RP;4c164200-20c0-11d0-a768-00aa006e0529;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIIOID;RP;4c164200-20c0-11d0-a768-00aa006e0529;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIOID;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIIOID;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIOID;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIIOID;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIOID;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIIOID;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIOID;RP;037088f8-0ae1-11d2-b422-00a0c968f939;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIIOID;RP;037088f8-0ae1-11d2-b422-00a0c968f939;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIID;RPWP;5b47d60f-6090-40b2-9f37-2a4de88f3063;;{DomainSid}-526)(OA;CIID;RPWP;5b47d60f-6090-40b2-9f37-2a4de88f3063;;{DomainSid}-527)(OA;CIIOID;SW;9b026da6-0d3c-465c-8bee-5199d7165cba;bf967a86-0de6-11d0-a285-00aa003049e2;CO)(OA;CIIOID;SW;9b026da6-0d3c-465c-8bee-5199d7165cba;bf967a86-0de6-11d0-a285-00aa003049e2;PS)(OA;CIIOID;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967a86-0de6-11d0-a285-00aa003049e2;ED)(OA;CIIOID;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967a9c-0de6-11d0-a285-00aa003049e2;ED)(OA;CIIOID;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967aba-0de6-11d0-a285-00aa003049e2;ED)(OA;CIIOID;WP;ea1b7b93-5e48-46d5-bc6c-4df4fda78a35;bf967a86-0de6-11d0-a285-00aa003049e2;PS)(OA;CIIOID;LCRPLORC;;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIIOID;LCRPLORC;;bf967a9c-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIOID;LCRPLORC;;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;OICIID;RPWP;3f78c3e5-f79a-46bd-a0b8-9d18116ddc79;;PS)(OA;CIID;RPWPCR;91e647de-d96f-4b70-9557-d63ff4f3ccd8;;PS)(A;CIID;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;{ForestSid}-519)(A;CIID;LC;;;RU)(A;CIID;CCLCSWRPWPLOCRSDRCWDWO;;;BA)"
                    }
                    DomainRoot = @{
                        InheritanceBlocked = $false
                        SDDL = "D:AI(A;;RP;;;WD)(A;;LCRPLORC;;;ED)(A;;LCRPLORC;;;AU)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;CI;CCLCSWRPWPLOCRSDRCWDWO;;;BA)(A;;RPRC;;;RU)(A;CI;LC;;;RU)(A;;CCLCSWRPWPLOCRRCWDWO;;;{DomainSid}-512)(A;CI;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;{ForestSid}-519)(OA;CIIO;SW;9b026da6-0d3c-465c-8bee-5199d7165cba;bf967a86-0de6-11d0-a285-00aa003049e2;CO)(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;ED)(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;ED)(OA;;CR;1131f6aa-9c07-11d1-f79f-00c04fc2dcd2;;ED)(OA;;CR;89e95b76-444d-4c62-991a-0facbeda640c;;ED)(OA;CIIO;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967aba-0de6-11d0-a285-00aa003049e2;ED)(OA;;CR;1131f6ae-9c07-11d1-f79f-00c04fc2dcd2;;ED)(OA;CIIO;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967a9c-0de6-11d0-a285-00aa003049e2;ED)(OA;CIIO;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967a86-0de6-11d0-a285-00aa003049e2;ED)(OA;CIIO;SW;9b026da6-0d3c-465c-8bee-5199d7165cba;bf967a86-0de6-11d0-a285-00aa003049e2;PS)(OA;CIIO;RPWPCR;91e647de-d96f-4b70-9557-d63ff4f3ccd8;;PS)(OA;CIIO;WP;ea1b7b93-5e48-46d5-bc6c-4df4fda78a35;bf967a86-0de6-11d0-a285-00aa003049e2;PS)(OA;OICI;RPWP;3f78c3e5-f79a-46bd-a0b8-9d18116ddc79;;PS)(OA;;CR;05c74c5e-4deb-43b4-bd9f-86664c2a7fd5;;AU)(OA;;CR;ccc2dc7d-a6ad-4a7a-8846-c04e3cc53501;;AU)(OA;;CR;280f369c-67c7-438e-ae98-1d46f3c6f541;;AU)(OA;;RP;b8119fd0-04f6-4762-ab7a-4986c76b3f9a;;AU)(OA;;CR;1131f6ae-9c07-11d1-f79f-00c04fc2dcd2;;BA)(OA;;CR;1131f6ad-9c07-11d1-f79f-00c04fc2dcd2;;BA)(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;BA)(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;BA)(OA;;CR;1131f6aa-9c07-11d1-f79f-00c04fc2dcd2;;BA)(OA;;CR;89e95b76-444d-4c62-991a-0facbeda640c;;BA)(OA;CIIO;LCRPLORC;;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIO;LCRPLORC;;bf967a9c-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIO;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIO;LCRPLORC;;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;;RP;b8119fd0-04f6-4762-ab7a-4986c76b3f9a;;RU)(OA;CIIO;RP;037088f8-0ae1-11d2-b422-00a0c968f939;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIIO;RP;4c164200-20c0-11d0-a768-00aa006e0529;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIO;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIIO;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;;RP;c7407360-20bf-11d0-a768-00aa006e0529;;RU)(OA;CIIO;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIIO;RP;037088f8-0ae1-11d2-b422-00a0c968f939;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIO;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIO;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIIO;RP;4c164200-20c0-11d0-a768-00aa006e0529;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;;CR;e2a36dc9-ae17-47c3-b58b-be34c55ba633;;S-1-5-32-557)(OA;;CR;1131f6aa-9c07-11d1-f79f-00c04fc2dcd2;;{ForestSid}-498)(OA;;CR;1131f6ad-9c07-11d1-f79f-00c04fc2dcd2;;{DomainSid}-516)(OA;;CR;3e0f7e18-2c7a-4c10-ba82-4d926db99a3e;;{DomainSid}-522)(OA;CI;RPWP;5b47d60f-6090-40b2-9f37-2a4de88f3063;;{DomainSid}-526)(OA;CI;RPWP;5b47d60f-6090-40b2-9f37-2a4de88f3063;;{DomainSid}-527)"
                    }
                    AdminSDHolder = @{
                        InheritanceBlocked = $true
                        SDDL = "D:PAI(A;;LCRPLORC;;;AU)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCDCLCSWRPWPLOCRSDRCWDWO;;;BA)(A;;CCDCLCSWRPWPLOCRRCWDWO;;;{DomainSid}-512)(A;;CCDCLCSWRPWPLOCRRCWDWO;;;{ForestSid}-519)(OA;;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;;WD)(OA;CI;RPWPCR;91e647de-d96f-4b70-9557-d63ff4f3ccd8;;PS)(OA;;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;;PS)(OA;;RP;037088f8-0ae1-11d2-b422-00a0c968f939;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;;RP;037088f8-0ae1-11d2-b422-00a0c968f939;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;;RP;4c164200-20c0-11d0-a768-00aa006e0529;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;;LCRPLORC;;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;;LCRPLORC;;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;;RP;4c164200-20c0-11d0-a768-00aa006e0529;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;;RP;46a9b11d-60ae-405a-b7e8-ff8a58d456d2;;S-1-5-32-560)(OA;;RPWP;6db69a1c-9422-11d1-aebd-0000f80367c1;;S-1-5-32-561)(OA;;RPWP;5805bc62-bdc9-4428-a5e2-856a0f4c185e;;S-1-5-32-561)(OA;;RPWP;bf967a7f-0de6-11d0-a285-00aa003049e2;;{DomainSid}-517)"
                    }
                }
            },
            @{
                DomainType = "Child Domain"
                DomainSid = "{DomainSid}"
                ForestSid = "{ForestSid}"
                SDDL = @{
                    DomainControllers = @{
                        InheritanceBlocked = $false
                        SDDL = "D:AI(A;;LCRPLORC;;;ED)(A;;LCRPLORC;;;AU)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCLCSWRPWPLOCRRCWDWO;;;{DomainSid}-512)(OA;CIIOID;RP;4c164200-20c0-11d0-a768-00aa006e0529;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIIOID;RP;4c164200-20c0-11d0-a768-00aa006e0529;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIOID;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIIOID;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIOID;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIIOID;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIOID;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIIOID;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIOID;RP;037088f8-0ae1-11d2-b422-00a0c968f939;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIIOID;RP;037088f8-0ae1-11d2-b422-00a0c968f939;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIID;RPWP;5b47d60f-6090-40b2-9f37-2a4de88f3063;;{DomainSid}-526)(OA;CIID;RPWP;5b47d60f-6090-40b2-9f37-2a4de88f3063;;{ForestSid}-527)(OA;CIIOID;SW;9b026da6-0d3c-465c-8bee-5199d7165cba;bf967a86-0de6-11d0-a285-00aa003049e2;CO)(OA;CIIOID;SW;9b026da6-0d3c-465c-8bee-5199d7165cba;bf967a86-0de6-11d0-a285-00aa003049e2;PS)(OA;CIIOID;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967a86-0de6-11d0-a285-00aa003049e2;ED)(OA;CIIOID;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967a9c-0de6-11d0-a285-00aa003049e2;ED)(OA;CIIOID;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967aba-0de6-11d0-a285-00aa003049e2;ED)(OA;CIIOID;WP;ea1b7b93-5e48-46d5-bc6c-4df4fda78a35;bf967a86-0de6-11d0-a285-00aa003049e2;PS)(OA;CIIOID;LCRPLORC;;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIIOID;LCRPLORC;;bf967a9c-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIOID;LCRPLORC;;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;OICIID;RPWP;3f78c3e5-f79a-46bd-a0b8-9d18116ddc79;;PS)(OA;CIID;RPWPCR;91e647de-d96f-4b70-9557-d63ff4f3ccd8;;PS)(A;CIID;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;{ForestSid}-519)(A;CIID;LC;;;RU)(A;CIID;CCLCSWRPWPLOCRSDRCWDWO;;;BA)"
                    }
                    DomainRoot = @{
                        InheritanceBlocked = $false
                        SDDL = "D:AI(A;;RP;;;WD)(A;;LCRPLORC;;;ED)(A;;LCRPLORC;;;AU)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;CI;CCLCSWRPWPLOCRSDRCWDWO;;;BA)(A;CI;LC;;;RU)(A;;RPRC;;;RU)(A;CI;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;{ForestSid}-519)(A;;CCLCSWRPWPLOCRRCWDWO;;;{DomainSid}-512)(OA;CIIO;SW;9b026da6-0d3c-465c-8bee-5199d7165cba;bf967a86-0de6-11d0-a285-00aa003049e2;CO)(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;ED)(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;ED)(OA;;CR;1131f6aa-9c07-11d1-f79f-00c04fc2dcd2;;ED)(OA;;CR;89e95b76-444d-4c62-991a-0facbeda640c;;ED)(OA;CIIO;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967aba-0de6-11d0-a285-00aa003049e2;ED)(OA;;CR;1131f6ae-9c07-11d1-f79f-00c04fc2dcd2;;ED)(OA;CIIO;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967a9c-0de6-11d0-a285-00aa003049e2;ED)(OA;CIIO;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967a86-0de6-11d0-a285-00aa003049e2;ED)(OA;CIIO;SW;9b026da6-0d3c-465c-8bee-5199d7165cba;bf967a86-0de6-11d0-a285-00aa003049e2;PS)(OA;CIIO;RPWPCR;91e647de-d96f-4b70-9557-d63ff4f3ccd8;;PS)(OA;CIIO;WP;ea1b7b93-5e48-46d5-bc6c-4df4fda78a35;bf967a86-0de6-11d0-a285-00aa003049e2;PS)(OA;OICI;RPWP;3f78c3e5-f79a-46bd-a0b8-9d18116ddc79;;PS)(OA;;CR;05c74c5e-4deb-43b4-bd9f-86664c2a7fd5;;AU)(OA;;CR;ccc2dc7d-a6ad-4a7a-8846-c04e3cc53501;;AU)(OA;;CR;280f369c-67c7-438e-ae98-1d46f3c6f541;;AU)(OA;;RP;b8119fd0-04f6-4762-ab7a-4986c76b3f9a;;AU)(OA;;CR;1131f6ae-9c07-11d1-f79f-00c04fc2dcd2;;BA)(OA;;CR;1131f6ad-9c07-11d1-f79f-00c04fc2dcd2;;BA)(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;BA)(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;BA)(OA;;CR;1131f6aa-9c07-11d1-f79f-00c04fc2dcd2;;BA)(OA;;CR;89e95b76-444d-4c62-991a-0facbeda640c;;BA)(OA;CIIO;LCRPLORC;;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIO;LCRPLORC;;bf967a9c-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIO;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIIO;LCRPLORC;;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;;RP;b8119fd0-04f6-4762-ab7a-4986c76b3f9a;;RU)(OA;CIIO;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIO;RP;4c164200-20c0-11d0-a768-00aa006e0529;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIO;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIIO;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;;RP;c7407360-20bf-11d0-a768-00aa006e0529;;RU)(OA;CIIO;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIO;RP;037088f8-0ae1-11d2-b422-00a0c968f939;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIO;RP;037088f8-0ae1-11d2-b422-00a0c968f939;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIIO;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIIO;RP;4c164200-20c0-11d0-a768-00aa006e0529;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;;CR;e2a36dc9-ae17-47c3-b58b-be34c55ba633;;S-1-5-32-557)(OA;;CR;1131f6aa-9c07-11d1-f79f-00c04fc2dcd2;;{ForestSid}-498)(OA;CI;RPWP;5b47d60f-6090-40b2-9f37-2a4de88f3063;;{ForestSid}-527)(OA;;CR;1131f6ad-9c07-11d1-f79f-00c04fc2dcd2;;{DomainSid}-516)(OA;;CR;3e0f7e18-2c7a-4c10-ba82-4d926db99a3e;;{DomainSid}-522)(OA;CI;RPWP;5b47d60f-6090-40b2-9f37-2a4de88f3063;;{DomainSid}-526)"
                    }
                    AdminSDHolder = @{
                        InheritanceBlocked = $true
                        SDDL = "D:PAI(A;;LCRPLORC;;;AU)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCDCLCSWRPWPLOCRSDRCWDWO;;;BA)(A;;CCDCLCSWRPWPLOCRRCWDWO;;;{ForestSid}-519)(A;;CCDCLCSWRPWPLOCRRCWDWO;;;{DomainSid}-512)(OA;;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;;WD)(OA;CI;RPWPCR;91e647de-d96f-4b70-9557-d63ff4f3ccd8;;PS)(OA;;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;;PS)(OA;;RP;037088f8-0ae1-11d2-b422-00a0c968f939;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;;RP;037088f8-0ae1-11d2-b422-00a0c968f939;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;;RP;4c164200-20c0-11d0-a768-00aa006e0529;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;;LCRPLORC;;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;;LCRPLORC;;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;;RP;4c164200-20c0-11d0-a768-00aa006e0529;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;;RP;46a9b11d-60ae-405a-b7e8-ff8a58d456d2;;S-1-5-32-560)(OA;;RPWP;6db69a1c-9422-11d1-aebd-0000f80367c1;;S-1-5-32-561)(OA;;RPWP;5805bc62-bdc9-4428-a5e2-856a0f4c185e;;S-1-5-32-561)(OA;;RPWP;bf967a7f-0de6-11d0-a285-00aa003049e2;;{DomainSid}-517)"
                    }
                }
            },
            @{
                DomainType = "Tree Root"
                DomainSid = "{DomainSid}"
                ForestSid = "{ForestSid}"
                SDDL = @{
                    DomainControllers = @{
                        InheritanceBlocked = $false
                        SDDL = "D:AI(A;;LCRPLORC;;;ED)(A;;LCRPLORC;;;AU)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCLCSWRPWPLOCRRCWDWO;;;{DomainSid}-512)(OA;CIIOID;RP;4c164200-20c0-11d0-a768-00aa006e0529;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIIOID;RP;4c164200-20c0-11d0-a768-00aa006e0529;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIOID;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIIOID;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIOID;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIIOID;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIOID;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIIOID;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIOID;RP;037088f8-0ae1-11d2-b422-00a0c968f939;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIIOID;RP;037088f8-0ae1-11d2-b422-00a0c968f939;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIID;RPWP;5b47d60f-6090-40b2-9f37-2a4de88f3063;;{DomainSid}-526)(OA;CIID;RPWP;5b47d60f-6090-40b2-9f37-2a4de88f3063;;{ForestSid}-527)(OA;CIIOID;SW;9b026da6-0d3c-465c-8bee-5199d7165cba;bf967a86-0de6-11d0-a285-00aa003049e2;CO)(OA;CIIOID;SW;9b026da6-0d3c-465c-8bee-5199d7165cba;bf967a86-0de6-11d0-a285-00aa003049e2;PS)(OA;CIIOID;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967a86-0de6-11d0-a285-00aa003049e2;ED)(OA;CIIOID;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967a9c-0de6-11d0-a285-00aa003049e2;ED)(OA;CIIOID;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967aba-0de6-11d0-a285-00aa003049e2;ED)(OA;CIIOID;WP;ea1b7b93-5e48-46d5-bc6c-4df4fda78a35;bf967a86-0de6-11d0-a285-00aa003049e2;PS)(OA;CIIOID;LCRPLORC;;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIIOID;LCRPLORC;;bf967a9c-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIOID;LCRPLORC;;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;OICIID;RPWP;3f78c3e5-f79a-46bd-a0b8-9d18116ddc79;;PS)(OA;CIID;RPWPCR;91e647de-d96f-4b70-9557-d63ff4f3ccd8;;PS)(A;CIID;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;{ForestSid}-519)(A;CIID;LC;;;RU)(A;CIID;CCLCSWRPWPLOCRSDRCWDWO;;;BA)"
                    }
                    DomainRoot = @{
                        InheritanceBlocked = $false
                        SDDL = "D:AI(A;;RP;;;WD)(A;;LCRPLORC;;;ED)(A;;LCRPLORC;;;AU)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;CI;CCLCSWRPWPLOCRSDRCWDWO;;;BA)(A;CI;LC;;;RU)(A;;RPRC;;;RU)(A;CI;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;{ForestSid}-519)(A;;CCLCSWRPWPLOCRRCWDWO;;;{DomainSid}-512)(OA;CIIO;SW;9b026da6-0d3c-465c-8bee-5199d7165cba;bf967a86-0de6-11d0-a285-00aa003049e2;CO)(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;ED)(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;ED)(OA;;CR;1131f6aa-9c07-11d1-f79f-00c04fc2dcd2;;ED)(OA;;CR;89e95b76-444d-4c62-991a-0facbeda640c;;ED)(OA;CIIO;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967aba-0de6-11d0-a285-00aa003049e2;ED)(OA;;CR;1131f6ae-9c07-11d1-f79f-00c04fc2dcd2;;ED)(OA;CIIO;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967a9c-0de6-11d0-a285-00aa003049e2;ED)(OA;CIIO;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967a86-0de6-11d0-a285-00aa003049e2;ED)(OA;CIIO;SW;9b026da6-0d3c-465c-8bee-5199d7165cba;bf967a86-0de6-11d0-a285-00aa003049e2;PS)(OA;CIIO;RPWPCR;91e647de-d96f-4b70-9557-d63ff4f3ccd8;;PS)(OA;CIIO;WP;ea1b7b93-5e48-46d5-bc6c-4df4fda78a35;bf967a86-0de6-11d0-a285-00aa003049e2;PS)(OA;OICI;RPWP;3f78c3e5-f79a-46bd-a0b8-9d18116ddc79;;PS)(OA;;CR;05c74c5e-4deb-43b4-bd9f-86664c2a7fd5;;AU)(OA;;CR;ccc2dc7d-a6ad-4a7a-8846-c04e3cc53501;;AU)(OA;;CR;280f369c-67c7-438e-ae98-1d46f3c6f541;;AU)(OA;;RP;b8119fd0-04f6-4762-ab7a-4986c76b3f9a;;AU)(OA;;CR;1131f6ae-9c07-11d1-f79f-00c04fc2dcd2;;BA)(OA;;CR;1131f6ad-9c07-11d1-f79f-00c04fc2dcd2;;BA)(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;BA)(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;BA)(OA;;CR;1131f6aa-9c07-11d1-f79f-00c04fc2dcd2;;BA)(OA;;CR;89e95b76-444d-4c62-991a-0facbeda640c;;BA)(OA;CIIO;LCRPLORC;;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIO;LCRPLORC;;bf967a9c-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIO;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIIO;LCRPLORC;;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;;RP;b8119fd0-04f6-4762-ab7a-4986c76b3f9a;;RU)(OA;CIIO;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIO;RP;4c164200-20c0-11d0-a768-00aa006e0529;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIO;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIIO;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;;RP;c7407360-20bf-11d0-a768-00aa006e0529;;RU)(OA;CIIO;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIO;RP;037088f8-0ae1-11d2-b422-00a0c968f939;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIO;RP;037088f8-0ae1-11d2-b422-00a0c968f939;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIIO;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIIO;RP;4c164200-20c0-11d0-a768-00aa006e0529;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;;CR;e2a36dc9-ae17-47c3-b58b-be34c55ba633;;S-1-5-32-557)(OA;;CR;1131f6aa-9c07-11d1-f79f-00c04fc2dcd2;;{ForestSid}-498)(OA;CI;RPWP;5b47d60f-6090-40b2-9f37-2a4de88f3063;;{ForestSid}-527)(OA;;CR;1131f6ad-9c07-11d1-f79f-00c04fc2dcd2;;{DomainSid}-516)(OA;;CR;3e0f7e18-2c7a-4c10-ba82-4d926db99a3e;;{DomainSid}-522)(OA;CI;RPWP;5b47d60f-6090-40b2-9f37-2a4de88f3063;;{DomainSid}-526)"
                    }
                    AdminSDHolder = @{
                        InheritanceBlocked = $true
                        SDDL = "D:PAI(A;;LCRPLORC;;;AU)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCDCLCSWRPWPLOCRSDRCWDWO;;;BA)(A;;CCDCLCSWRPWPLOCRRCWDWO;;;{ForestSid}-519)(A;;CCDCLCSWRPWPLOCRRCWDWO;;;{DomainSid}-512)(OA;;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;;WD)(OA;CI;RPWPCR;91e647de-d96f-4b70-9557-d63ff4f3ccd8;;PS)(OA;;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;;PS)(OA;;RP;037088f8-0ae1-11d2-b422-00a0c968f939;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;;RP;037088f8-0ae1-11d2-b422-00a0c968f939;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;;RP;4c164200-20c0-11d0-a768-00aa006e0529;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;;LCRPLORC;;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;;LCRPLORC;;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;;RP;4c164200-20c0-11d0-a768-00aa006e0529;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;;RP;46a9b11d-60ae-405a-b7e8-ff8a58d456d2;;S-1-5-32-560)(OA;;RPWP;6db69a1c-9422-11d1-aebd-0000f80367c1;;S-1-5-32-561)(OA;;RPWP;5805bc62-bdc9-4428-a5e2-856a0f4c185e;;S-1-5-32-561)(OA;;RPWP;bf967a7f-0de6-11d0-a285-00aa003049e2;;{DomainSid}-517)"
                    }
                }
            }
        )

        # Validate BaselineArray
        if (-not $script:BaselineArray -or $script:BaselineArray.Count -eq 0) {
            Write-IdentIRLog -Message "BaselineArray is empty or not defined" -TypeName Error -ForegroundColor Red
            $script:report.Errors.Add("BaselineArray is empty or not defined")
            throw "BaselineArray is empty or not defined"
        }
        Write-IdentIRLog -Message "BaselineArray contains $($script:BaselineArray.Count) domain configuration(s)" -TypeName Info -ForegroundColor Cyan

        $ErrorActionPreference = 'Stop'
        if (-not (Get-Variable -Name ForestContext -Scope Script -ErrorAction SilentlyContinue)) { $script:ForestContext = $null }
        if (-not (Get-Variable -Name allDCs -Scope Script -ErrorAction SilentlyContinue)) { $script:allDCs = $null }
        if (-not (Get-Variable -Name privGroups -Scope Script -ErrorAction SilentlyContinue)) { $script:privGroups = $null }
        Set-StrictMode -Version Latest
        $isWhatIf = -not $Execute.IsPresent
        $modeText = if ($isWhatIf) { 'WhatIf=True' } else { 'WhatIf=False' }

        # Static GroupNames list
        $GroupNames = @(
            'Access Control Assistance Operators', 
            'Account Operators', 
            'Administrators',
            'Allowed RODC Password Replication Group', 
            'Backup Operators',
            'Certificate Service DCOM Access', 
            'Cert Publishers', 
            'Cloneable Domain Controllers',
            'Cryptographic Operators', 
            'Distributed Com Users', 
            'Denied RODC Password Replication Group',
            'DNSAdmins', 
            'DnsUpdateProxy', 
            'Domain Admins', 
            'Domain Guests',
            'Enterprise Admins', 
            'Enterprise Key Admins', 
            'Event Log Readers',
            'Group Policy Creator Owners', 
            'Guests', 
            'Hyper-V Administrators', 
            'IIS_IUSRS',
            'Incoming Forest Trust Builders', 
            'Key Admins', 
            'Network Configuration Operators',
            'OpenSSH Users', 
            'Performance Log Users', 
            'Pre-Windows 2000 Compatible Access',
            'Print Operators', 
            'Protected Users', 
            'RAS and IAS Servers', 
            'RDS Endpoint Servers',
            'RDS Management Servers', 
            'RDS Remote Access Servers', 
            'Remote Desktop Users',
            'Remote Management Users', 
            'Replicator', 
            'Schema Admins', 
            'Server Operators',
            'Storage Replica Administrators', 
            'Windows Authorization Access Group'
        )

        # Forest-wide groups
        $ForestWideGroups = @('Enterprise Admins', 
        'Enterprise Key Admins', 
        'Incoming Forest Trust Builders', 
        'Schema Admins')

        function Escape-LdapValue {
            param([string]$Value)
            return $Value.Replace('\','\5c').Replace('*','\2a').Replace('(','\28').Replace(')','\29').Replace("`0",'\00')
        }

        function Get-DomainFromDN {
            param([string]$DN)
            $m = [regex]::Matches($DN,'(?i)DC=([^,]+)')
            if ($m.Count -eq 0) { return $null }
            return (($m | ForEach-Object { $_.Groups[1].Value }) -join '.')
        }

        function Get-ServerForDN {
            param([string]$DN,[object[]]$Contexts,[string]$Fallback)
            $dom = Get-DomainFromDN -DN $DN
            if (-not $dom) { return $Fallback }
            $match = $Contexts | Where-Object { $_.Name -eq $dom } | Select-Object -First 1
            if ($match -and $match.PDC) { return $match.PDC } else { return $Fallback }
        }

        function Get-BaselineByDomainType {
            param([Parameter(Mandatory)][string]$DomainType)
            $want = if ($null -ne $DomainType) { $DomainType.Trim() } else { '' }
            if ([string]::IsNullOrWhiteSpace($want)) { throw "Empty DomainType" }
            $baseline = $script:BaselineArray | Where-Object {
                $dt = $_.DomainType
                if ($null -eq $dt) { $dt = "" }
                ($dt -ceq $want) -or ($dt -eq $want)
            } | Select-Object -First 1
            if (-not $baseline) { throw "No baseline found for DomainType: '$DomainType'" }
            return $baseline
        }

        function Resolve-BaselineContainer {
            param(
                [Parameter(Mandatory)][psobject]$Baseline,
                [Parameter(Mandatory)][string]$ContainerKey
            )
            # Map the container keys to the actual baseline SDDL property names
            # The baseline uses: DomainControllers, DomainRoot, AdminSDHolder
            $map = @{
                'DomainRoot' = @('DomainRoot')
                'DomainControllersOU' = @('DomainControllers','Domain Controllers','DomainControllersOU')
                'AdminSDHolder' = @('AdminSDHolder','Admin SD Holder')
            }
            
            $candidates = $map[$ContainerKey]
            if (-not $candidates) { 
                throw "Unknown container key '$ContainerKey'. Valid keys: $($map.Keys -join ', ')"
            }
            
            $sddlNode = $null
            
            foreach ($name in $candidates) {
                # Check if the key exists in the hashtable (case-sensitive first)
                if ($Baseline.SDDL.ContainsKey($name)) { 
                    $sddlNode = $Baseline.SDDL[$name]
                    break 
                }
                
                foreach ($key in $Baseline.SDDL.Keys) {
                    if ($key -ieq $name) { 
                        $sddlNode = $Baseline.SDDL[$key]
                        break 
                    }
                }
                if ($sddlNode) { break }
            }
            
            if (-not $sddlNode) { 
                $availableKeys = ($Baseline.SDDL.Keys | Sort-Object) -join ', '
                throw "Baseline for DomainType '$($Baseline.DomainType)' is missing container '$ContainerKey'. Tried: $($candidates -join ', '). Available in baseline: $availableKeys"
            }
            
            # Validate the node has required properties
            if (-not $sddlNode.SDDL) {
                throw "Container '$ContainerKey' node is missing SDDL property"
            }
            if ($null -eq $sddlNode.InheritanceBlocked) {
                throw "Container '$ContainerKey' node is missing InheritanceBlocked property"
            }
            
            return $sddlNode
        }

        function Get-CleanSDDL {
            param(
                [Parameter(Mandatory)][string]$DomainType,
                [Parameter(Mandatory)][string]$ContainerType,
                [Parameter(Mandatory)][string]$ForestRootSID,
                [Parameter(Mandatory)][string]$DomainSID
            )
            try {
                $baseline = Get-BaselineByDomainType -DomainType $DomainType
                $node = Resolve-BaselineContainer -Baseline $baseline -ContainerKey $ContainerType
                if (-not $node.SDDL) { throw "Container node has no SDDL string" }
                if ($null -eq $node.InheritanceBlocked) { throw "Container node missing InheritanceBlocked" }
                $expanded = $node.SDDL.Replace('{DomainSid}', $DomainSID).Replace('{ForestSid}', $ForestRootSID)
                return @{ SDDL = $expanded; InheritanceBlocked = [bool]$node.InheritanceBlocked }
            } catch {
                Write-IdentIRLog -Message "Failed to get baseline for $DomainType / ${ContainerType}: $($_.Exception.Message)" -TypeName Error -ForegroundColor Red
                $script:report.Errors.Add("Failed to get baseline for $DomainType / ${ContainerType}: $($_.Exception.Message)")
                throw
            }
        }

        function Get-AceSignature {
            param([Parameter(Mandatory)]$Ace)
            if ($Ace -isnot [System.DirectoryServices.ActiveDirectoryAccessRule]) { return $null }
            $sid = $Ace.IdentityReference.Value
            $type = $Ace.AccessControlType
            $mask = [int]$Ace.ActiveDirectoryRights
            $flags = [int]$Ace.InheritanceType
            $ot = if ($Ace.ObjectType -ne [Guid]::Empty) { $Ace.ObjectType.Guid } else { "" }
            $iot = if ($Ace.InheritedObjectType -ne [Guid]::Empty) { $Ace.InheritedObjectType.Guid } else { "" }
            return ("{0}|{1}|{2}|{3}|{4}|{5}" -f $sid,$type,$mask,$flags,$ot,$iot)
        }

        function Get-DaclSignatureSet {
            param([Parameter(Mandatory)][string]$Sddl)
            try {
                $sd = New-Object System.DirectoryServices.ActiveDirectorySecurity
                $sd.SetSecurityDescriptorSddlForm($Sddl,[System.Security.AccessControl.AccessControlSections]::All)
                $prot = if ($sd.AreAccessRulesProtected) { "P" } else { "NP" }
                $sigs = New-Object System.Collections.Generic.List[string]
                foreach ($ace in $sd.GetAccessRules($true,$true,[System.Security.Principal.SecurityIdentifier])) {
                    $sig = Get-AceSignature -Ace $ace
                    if ($sig) { $sigs.Add($sig) }
                }
                return ,@($prot, ($sigs | Sort-Object -Unique))
            } catch {
                Write-IdentIRLog -Message "Failed to get DACL signature set: $($_.Exception.Message)" -TypeName Warning -ForegroundColor Yellow
                $script:report.Errors.Add("Failed to get DACL signature set: $($_.Exception.Message)")
                return ,@("ERROR", @())
            }
        }

        function Compare-SddlToClean {
            param(
                [Parameter(Mandatory)]$ADObject,
                [Parameter(Mandatory)][string]$CleanSDDL,
                [Parameter(Mandatory)][bool]$BaselineInheritanceBlocked,
                [Parameter(Mandatory)][string]$ContainerName
            )
            try {
                $currentRaw = $ADObject.psbase.ObjectSecurity.GetSecurityDescriptorSddlForm([System.Security.AccessControl.AccessControlSections]::Access)
                $currentInheritanceBlocked = $ADObject.psbase.ObjectSecurity.AreAccessRulesProtected
                $hasAdminCount = ($ADObject.Properties.Contains('adminCount') -and $ADObject.Properties['adminCount'].Value -eq 1)
                $inheritanceMatch = ($currentInheritanceBlocked -eq $BaselineInheritanceBlocked)
                $curSet = Get-DaclSignatureSet -Sddl $currentRaw
                $baseSet = Get-DaclSignatureSet -Sddl $CleanSDDL
                $protCur, $sigsCur = $curSet
                $protBase, $sigsBase = $baseSet
                if ($protCur -eq 'ERROR' -or $protBase -eq 'ERROR') {
                    Write-IdentIRLog -Message "[$($ContainerName)] Error parsing SDDL" -TypeName Warning -ForegroundColor Yellow
                    $script:report.Errors.Add("Error parsing SDDL for ${ContainerName}")
                    return @{
                        NeedsChange = $true; InheritanceMatch = $inheritanceMatch; DaclMatch = $false
                        CleanSD = $CleanSDDL; CurrentSD = $currentRaw; Reason = "Parser error"
                        HasAdminCount = $hasAdminCount; Adds = 0; Removes = 0
                    }
                }
                $cmp = Compare-Object -ReferenceObject $sigsCur -DifferenceObject $sigsBase -IncludeEqual:$false
                $currentOnly = @($cmp | Where-Object SideIndicator -eq '<=' | ForEach-Object InputObject)
                $baselineOnly = @($cmp | Where-Object SideIndicator -eq '=>' | ForEach-Object InputObject)
                $daclMatch = ($currentOnly.Count -eq 0 -and $baselineOnly.Count -eq 0)
                $protMatch = ($protCur -eq $protBase)
                $needsChange = (-not $daclMatch) -or (-not $protMatch) -or (-not $inheritanceMatch)
                if ($needsChange) {
                    $inhStatus = if ($inheritanceMatch) { "inheritance OK" } else { "inheritance mismatch" }
                    Write-IdentIRLog -Message "[$($ContainerName)] [WHATIF] Would reset: add $($baselineOnly.Count), remove $($currentOnly.Count), $inhStatus" -TypeName Info -ForegroundColor White
                } else {
                    Write-IdentIRLog -Message "[$($ContainerName)] Matches baseline" -TypeName Info -ForegroundColor Green
                }
                return @{
                    NeedsChange = $needsChange
                    InheritanceMatch = $inheritanceMatch
                    DaclMatch = $daclMatch
                    ProtMatch = $protMatch
                    CleanSD = $CleanSDDL
                    CurrentSD = $currentRaw
                    CurrentOnlyAces = $currentOnly
                    BaselineOnlyAces = $baselineOnly
                    Adds = $baselineOnly.Count
                    Removes = $currentOnly.Count
                    CurrentInheritanceBlocked = $currentInheritanceBlocked
                    BaselineInheritanceBlocked = $BaselineInheritanceBlocked
                    HasAdminCount = $hasAdminCount
                }
            } catch {
                Write-IdentIRLog -Message "[$($ContainerName)] Failed to compare SDDL: $($_.Exception.Message)" -TypeName Error -ForegroundColor Red
                $script:report.Errors.Add("Failed to compare SDDL for ${ContainerName}: $($_.Exception.Message)")
                return @{
                    NeedsChange = $true; InheritanceMatch = $false; DaclMatch = $false
                    Reason = $_.Exception.Message; HasAdminCount = $false
                    Adds = 0; Removes = 0
                }
            }
        }

        function Reset-ObjectAcl {
            param(
                [Parameter(Mandatory)]$ADObject,
                [Parameter(Mandatory)][string]$CleanSD,
                [Parameter()][bool]$RemoveAdminCount=$false,
                [Parameter()][bool]$AllowInheritance=$true,
                [Parameter()][switch]$AccessOnly
            )
            try {
                $sd = New-Object System.DirectoryServices.ActiveDirectorySecurity
                $section = if ($AccessOnly.IsPresent) { [System.Security.AccessControl.AccessControlSections]::Access } else { [System.Security.AccessControl.AccessControlSections]::All }
                $sd.SetSecurityDescriptorSddlForm($CleanSD, $section)
                if ($AllowInheritance) {
                    $sd.SetAccessRuleProtection($false, $true)
                } else {
                    $sd.SetAccessRuleProtection($true, $true)
                }
                $ADObject.psbase.ObjectSecurity = $sd
                if ($RemoveAdminCount -and $ADObject.Properties.Contains('adminCount')) {
                    $ADObject.Properties['adminCount'].Clear()
                }
                $ADObject.CommitChanges()
                Write-IdentIRLog -Message "Successfully reset ACL for $($ADObject.distinguishedName)" -TypeName Info -ForegroundColor Green
                return $true
            } catch {
                Write-IdentIRLog -Message "Failed to reset ACL for $($ADObject.distinguishedName): $($_.Exception.Message)" -TypeName Error -ForegroundColor Red
                $script:report.Errors.Add("Failed to reset ACL for $($ADObject.distinguishedName): $($_.Exception.Message)")
                return $false
            }
        }

        function Get-NestedGroupMembers {
    param([Parameter(Mandatory)][string]$GroupDN,[Parameter(Mandatory)][string]$Server)
    $seen = New-Object System.Collections.Generic.HashSet[string] ([StringComparer]::OrdinalIgnoreCase)
    $out = New-Object System.Collections.Generic.List[psobject]
    $q = New-Object System.Collections.Generic.Queue[object]
    $q.Enqueue($GroupDN)
    while ($q.Count -gt 0) {
        $cur = [string]$q.Dequeue()
        if (-not $seen.Add($cur)) { continue }
        try {
            $g = [adsi]"LDAP://$Server/$cur"
            foreach ($m in @($g.Properties['member'])) {
                if ($m -is [string] -and $m -match '^CN=.*?,DC=.*') {
                    try {
                        $obj = [adsi]"LDAP://$Server/$m"
                        $cls = @($obj.Properties['objectClass'])
                        $sam = if ($obj.Properties.Contains("sAMAccountName")) { [string]$obj.Properties["sAMAccountName"].Value } else { "Unknown" }
                        if ($cls -contains 'group') {
                            $q.Enqueue($m)
                        } else {
                            $out.Add([pscustomobject]@{DN=$m; SamAccountName=$sam})
                        }
                    } catch {
                        $out.Add([pscustomobject]@{DN=$m; SamAccountName="Unknown"})
                        $script:report.Errors.Add("Failed to retrieve object $m in Get-NestedGroupMembers: $($_.Exception.Message)")
                    }
                }
            }
        } catch {
            Write-IdentIRLog -Message "[Get-NestedGroupMembers] Failed to process group members for $GroupDN on ${Server}: $($_.Exception.Message)" -TypeName Error -ForegroundColor Red
            $script:report.Errors.Add("Failed to process group members for ${GroupDN}: $($_.Exception.Message)")
        }
    }
    return ,$out
}

        function Get-DNByRid {
    param(
        [Parameter(Mandatory)][string]$DomainSid,
        [Parameter(Mandatory)][string]$Server,
        [Parameter(Mandatory)][string]$SearchBase,
        [Parameter(Mandatory)][int]$Rid
    )
    try {
        $sid = "$DomainSid-$Rid"
        $s = New-Object System.DirectoryServices.DirectorySearcher
        $s.SearchRoot = [adsi]"LDAP://$Server/$SearchBase"
        $s.Filter = "(objectSid=$sid)"
        $s.PageSize = 1
        [void]$s.PropertiesToLoad.Add("distinguishedName")
        [void]$s.PropertiesToLoad.Add("sAMAccountName")
        $r = $s.FindOne()
        $s.Dispose()
        if ($r) {
            return [pscustomobject]@{
                DN = [string]$r.Properties['distinguishedName'][0]
                SamAccountName = if ($r.Properties['sAMAccountName']) { [string]$r.Properties['sAMAccountName'][0] } else { "Unknown" }
            }
        }
        return $null
    } catch {
        Write-IdentIRLog -Message "[Get-DNByRid] Failed to resolve DN for SID $sid on ${Server}: $($_.Exception.Message)" -TypeName Error -ForegroundColor Red
        $script:report.Errors.Add("Failed to resolve DN for SID ${sid}: $($_.Exception.Message)")
        return $null
    }
}

        function Get-DefaultGroupMemberships {
        param(
            [Parameter(Mandatory)][string]$GroupName,
            [Parameter(Mandatory)][string]$DomainType,
            [Parameter(Mandatory)][string]$DomainSID,
            [Parameter(Mandatory)][string]$ForestRootSID,
            [Parameter(Mandatory)][string]$Server,
            [Parameter(Mandatory)][string]$SearchBase,
            [Parameter(Mandatory)][string]$ForestRootDN
        )
        $defaults = New-Object System.Collections.Generic.List[psobject]
        $typeMap = $script:DefaultGroupMemberships[$DomainType]
        if (-not $typeMap) { return ,@() }
        $entries = $typeMap[$GroupName]
        if (-not $entries) { return ,@() }
        foreach ($e in $entries) {
            $rid = [int]$e.RID
            $resolveSid = $DomainSID
            $resolveBase = $SearchBase
            if (@(518,519) -contains $rid -and $ForestRootSID) {
                $resolveSid = $ForestRootSID
                $resolveBase = $ForestRootDN
            }
            $result = Get-DNByRid -DomainSid $resolveSid -Server $Server -SearchBase $resolveBase -Rid $rid
            if ($result) { $defaults.Add([pscustomobject]@{ DN=$result.DN; SamAccountName=$result.SamAccountName }) }
        }
        return ,$defaults
    }

        # Default Group Membership Map
        $script:DefaultGroupMemberships = @{
            'Forest Root' = @{
                'Administrators' = @(@{ Name='Administrator'; RID='500' }, @{ Name='Domain Admins'; RID='512' }, @{ Name='Enterprise Admins'; RID='519' })
                'Guests' = @(@{ Name='Guest'; RID='501' }, @{ Name='Domain Guests'; RID='514' })
                'Domain Admins' = @(@{ Name='Administrator'; RID='500' })
                'Enterprise Admins' = @()
                'Denied RODC Password Replication Group' = @(
                    @{ Name='Domain Admins'; RID='512' }, @{ Name='Domain Controllers'; RID='516' }, @{ Name='Cert Publishers'; RID='517' },
                    @{ Name='Schema Admins'; RID='518' }, @{ Name='Enterprise Admins'; RID='519' }, @{ Name='Group Policy Creator Owners'; RID='520' },
                    @{ Name='Read-only Domain Controllers'; RID='521' }
                )
            }
            'Child Domain' = @{
                'Administrators' = @(@{ Name='Administrator'; RID='500' }, @{ Name='Domain Admins'; RID='512' }, @{ Name='Enterprise Admins'; RID='519' })
                'Guests' = @(@{ Name='Guest'; RID='501' }, @{ Name='Domain Guests'; RID='514' })
                'Domain Admins' = @(@{ Name='Administrator'; RID='500' })
                'Denied RODC Password Replication Group' = @(
                    @{ Name='Domain Admins'; RID='512' }, @{ Name='Domain Controllers'; RID='516' }, @{ Name='Cert Publishers'; RID='517' },
                    @{ Name='Schema Admins'; RID='518' }, @{ Name='Enterprise Admins'; RID='519' }, @{ Name='Group Policy Creator Owners'; RID='520' },
                    @{ Name='Read-only Domain Controllers'; RID='521' }
                )
            }
            'Tree Root' = @{
                'Administrators' = @(@{ Name='Administrator'; RID='500' }, @{ Name='Domain Admins'; RID='512' }, @{ Name='Enterprise Admins'; RID='519' })
                'Guests' = @(@{ Name='Guest'; RID='501' }, @{ Name='Domain Guests'; RID='514' })
                'Domain Admins' = @(@{ Name='Administrator'; RID='500' })
                'Denied RODC Password Replication Group' = @(
                    @{ Name='Domain Admins'; RID='512' }, @{ Name='Domain Controllers'; RID='516' }, @{ Name='Cert Publishers'; RID='517' },
                    @{ Name='Schema Admins'; RID='518' }, @{ Name='Enterprise Admins'; RID='519' }, @{ Name='Group Policy Creator Owners'; RID='520' },
                    @{ Name='Read-only Domain Controllers'; RID='521' }
                )
            }
        }

        # Report
        $script:report = [PSCustomObject]@{
            Mode = $modeText; StartTime = Get-Date; EndTime = $null
            DomainsProcessed = [System.Collections.Generic.List[string]]::new()
            GroupsProcessed = [System.Collections.Generic.List[string]]::new()
            PrivilegedUsers = [System.Collections.Generic.List[PSObject]]::new()
            AccountsDisabled = [System.Collections.Generic.List[string]]::new()
            PasswordNeverExpiresRemoved = [System.Collections.Generic.List[string]]::new()
            SmartCardRequired = [System.Collections.Generic.List[string]]::new()
            PreauthRemoved = [System.Collections.Generic.List[string]]::new()
            NotDelegatedSet = [System.Collections.Generic.List[string]]::new()
            PasswordsReset = [System.Collections.Generic.List[string]]::new()
            PrimaryGroupFixed = [System.Collections.Generic.List[string]]::new()
            MembershipsRevoked = [System.Collections.Generic.List[string]]::new()
            AclsReset = [System.Collections.Generic.List[string]]::new()
            ContainerAclsReset = [System.Collections.Generic.List[string]]::new()
            ExcludedAccounts = [System.Collections.Generic.List[string]]::new()
            Errors = [System.Collections.Generic.List[string]]::new()
            ContainerComparisons = [System.Collections.Generic.List[PSObject]]::new()
            Stats = [PSCustomObject]@{
                Domains=0; Groups=0; PrivilegedUsers=0; AccountsDisabled=0
                PasswordNeverExpiresRemoved=0; SmartCardRequired=0; PreauthRemoved=0
                NotDelegatedSet=0; PasswordsReset=0; PrimaryGroupFixed=0
                MembershipsRevoked=0; AclsReset=0; ContainerAclsReset=0
                ContainerAclsNeedingReset=0; PerObjectAclsNeedingReset=0
            }
        }

        Write-IdentIRLog -Message "Starting Control Plane Disposition Cleanup ($modeText)" -TypeName Info -ForegroundColor Green
        try {
            $currentIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
            $script:currentUserSid = $currentIdentity.User.Value
            $script:currentUserName = $currentIdentity.Name
            Write-IdentIRLog -Message "Running as: $script:currentUserName" -TypeName Info -ForegroundColor Cyan
        } catch {
            Write-IdentIRLog -Message "Failed to determine current user: $($_.Exception.Message)" -TypeName Error -ForegroundColor Red
            $script:report.Errors.Add("Failed to determine current user: $($_.Exception.Message)")
            throw
        }

        if (-not $script:ForestContext) {
            $script:ForestContext = [ordered]@{ RootDN=$null; RootSID=$null; RootPDC=$null; Logged=$false }
        }
        $script:allDCs = [System.Collections.Generic.List[object]]::new()
        $script:privGroups = [System.Collections.Generic.List[psobject]]::new()
        }
        process {
            foreach ($dc in $IsolatedDCList) { $script:allDCs.Add($dc) }
        }
        end {
            if ($script:allDCs.Count -eq 0) {
                Write-IdentIRLog -Message "No domain controllers provided" -TypeName Error -ForegroundColor Red
                throw "No domain controllers provided"
            }
            Write-IdentIRLog -Message "Received $($script:allDCs.Count) DC(s)" -TypeName Info -ForegroundColor Cyan
            $onlineDCs = @($script:allDCs | Where-Object { $_.Online -eq $true })
            if ($onlineDCs.Count -eq 0) {
                Write-IdentIRLog -Message "No online DCs available" -TypeName Error -ForegroundColor Red
                throw "No online DCs available"
            }

            # Build Forest/Domain contexts
            Write-IdentIRLog -Message "Building domain & forest context..." -TypeName Info -ForegroundColor Cyan
            if (-not $script:ForestContext.RootDN -or -not $script:ForestContext.RootSID -or -not $script:ForestContext.RootPDC) {
                $anyDc = $onlineDCs[0]
                try {
                    $rootDse = [adsi]"LDAP://$($anyDc.FQDN)/RootDSE"
                    $forestRootDN = [string]$rootDse.Properties['rootDomainNamingContext'].Value
                    $configNC = [string]$rootDse.Properties['configurationNamingContext'].Value
                    $rootHost = $null
                    try {
                        $ds = New-Object System.DirectoryServices.DirectorySearcher
                        $ds.SearchRoot = [adsi]"LDAP://$($anyDc.FQDN)/CN=Sites,$configNC"
                        $ds.Filter = "(&(objectClass=nTDSDSA)(msDS-hasMasterNCs=$forestRootDN))"
                        $ds.PageSize = 1000
                        [void]$ds.PropertiesToLoad.Add("distinguishedName")
                        $res = $ds.FindOne()
                        if ($res) {
                            $ntdsDn = [string]$res.Properties["distinguishedName"][0]
                            $serverDn = ($ntdsDn -replace '^CN=NTDS Settings,')
                            $serverObj = [adsi]"LDAP://$($anyDc.FQDN)/$serverDn"
                            $rootHost = [string]$serverObj.Properties["dNSHostName"].Value
                        }
                        $ds.Dispose()
                    } catch {
                        Write-IdentIRLog -Message "Failed to resolve forest root PDC: $($_.Exception.Message)" -TypeName Error -ForegroundColor Red
                        $script:report.Errors.Add("Failed to resolve forest root PDC: $($_.Exception.Message)")
                    }
                    if (-not $rootHost) {
                        $rootDc = $onlineDCs | Where-Object { $_.DefaultNamingContext -eq $forestRootDN } | Select-Object -First 1
                        $rootHost = if ($rootDc) { $rootDc.FQDN } else { $anyDc.FQDN }
                    }
                    $forestRootSID = $null
                    try {
                        $domObj = [adsi]"LDAP://$rootHost/$forestRootDN"
                        $forestRootSID = (New-Object System.Security.Principal.SecurityIdentifier($domObj.Properties["objectSid"].Value,0)).Value
                    } catch {
                        Write-IdentIRLog -Message "Failed to resolve Forest Root SID from $rootHost/${forestRootDN}: $($_.Exception.Message)" -TypeName Error -ForegroundColor Red
                        $script:report.Errors.Add("Failed to resolve Forest Root SID from $rootHost/${forestRootDN}: $($_.Exception.Message)")
                        throw
                    }
                    $script:ForestContext.RootDN = $forestRootDN
                    $script:ForestContext.RootSID = $forestRootSID
                    $script:ForestContext.RootPDC = $rootHost
                } catch {
                    Write-IdentIRLog -Message "Failed to build forest context: $($_.Exception.Message)" -TypeName Error -ForegroundColor Red
                    $script:report.Errors.Add("Failed to build forest context: $($_.Exception.Message)")
                    throw
                }
            }

            if (-not $script:ForestContext.Logged) {
                Write-IdentIRLog -Message "Forest Root: $($script:ForestContext.RootDN) (SID: $($script:ForestContext.RootSID)) via $($script:ForestContext.RootPDC)" -TypeName Info -ForegroundColor Cyan
                $priorityTypes = @{ 'Forest Root' = 'Forest Root'; 'Child Domain' = 'Child Domain'; 'Tree Root' = 'Tree Root' }
                foreach ($dom in ($onlineDCs | Sort-Object @{ Expression = { $priorityTypes[$_.Type] } }, FQDN)) {
                    $typeLabel = $priorityTypes[$dom.Type]
                    Write-IdentIRLog -Message "${typeLabel}: $($dom.DefaultNamingContext) (SID: $($dom.DomainSid)) via $($dom.FQDN)" -TypeName Info -ForegroundColor Cyan
                }
                $script:ForestContext.Logged = $true
            }

            $priority = @{ 'Forest Root' = 1; 'Child Domain' = 2; 'Tree Root' = 3 }
            $script:domains = @(
                $onlineDCs | Group-Object -Property DefaultNamingContext | ForEach-Object {
                    $grp = $_.Group
                    $pdc = $grp | Where-Object { $_.IsPdcRoleOwner -eq $true } | Select-Object -First 1
                    if (-not $pdc) {
                        Write-IdentIRLog -Message "No PDC owner found for $($_.Name), selecting first online DC" -TypeName Warning -ForegroundColor Yellow
                        $pdc = $grp | Where-Object { $_.Online -eq $true } | Select-Object -First 1
                    }
                    if (-not $pdc) {
                        Write-IdentIRLog -Message "No online DCs available for $($_.Name)" -TypeName Error -ForegroundColor Red
                        $script:report.Errors.Add("No online DCs available for $($_.Name)")
                        return
                    }
                    try {
                        $domainObj = [adsi]"LDAP://$($pdc.FQDN)/$($pdc.DefaultNamingContext)"
                        $domainSid = (New-Object System.Security.Principal.SecurityIdentifier($domainObj.Properties["objectSid"].Value,0)).Value
                        [PSCustomObject]@{
                            Name = $pdc.Domain
                            Type = $pdc.Type
                            PDC = $pdc.FQDN
                            DefaultNC = $pdc.DefaultNamingContext
                            ConfigNC = $pdc.ConfigurationNamingContext
                            SID = $domainSid
                            ForestRootSID = $script:ForestContext.RootSID
                            ForestRootDN = $script:ForestContext.RootDN
                            ForestRootPDC = $script:ForestContext.RootPDC
                        }
                    } catch {
                        Write-IdentIRLog -Message "Failed to resolve SID for $($pdc.DefaultNamingContext) on $($pdc.FQDN): $($_.Exception.Message)" -TypeName Error -ForegroundColor Red
                        $script:report.Errors.Add("Failed to resolve SID for $($pdc.DefaultNamingContext) on $($pdc.FQDN): $($_.Exception.Message)")
                        return
                    }
                } | Sort-Object -Property @{ Expression = { $priority[$_.Type] } }, Name
            )

            if (-not $script:domains) {
                Write-IdentIRLog -Message "No valid domains processed" -TypeName Error -ForegroundColor Red
                throw "No valid domains processed"
            }

            # Exclusions
            Write-IdentIRLog -Message "Building exclusion list..." -TypeName Info -ForegroundColor White
            $excluded = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
            $excludePatterns = @('Guest','krbtgt*','DefaultAccount','msol*','IUSR*')
            $currentUserDomainSid = $script:currentUserSid -replace '-\d+$', ''
            $currentUserDomain = $script:domains | Where-Object { $_.SID -eq $currentUserDomainSid } | Select-Object -First 1
            foreach ($domain in $script:domains) {
                try {
                    foreach ($pattern in $excludePatterns) {
                        $isWildcard = $pattern.EndsWith('*')
                        $searchFilter = if ($isWildcard) {
                            $prefix = $pattern.TrimEnd('*')
                            $safe = Escape-LdapValue -Value $prefix
                            "(&(objectClass=user)(sAMAccountName=$safe*))"
                        } else {
                            $safe = Escape-LdapValue -Value $pattern
                            "(&(objectClass=user)(sAMAccountName=$safe))"
                        }
                        $s = New-Object System.DirectoryServices.DirectorySearcher
                        $s.SearchRoot = [adsi]"LDAP://$($domain.PDC)/$($domain.DefaultNC)"
                        $s.Filter = $searchFilter
                        $s.PageSize = 1000
                        [void]$s.PropertiesToLoad.Add("distinguishedName")
                        [void]$s.PropertiesToLoad.Add("sAMAccountName")
                        try {
                            $results = $s.FindAll()
                            foreach ($found in $results) {
                                $dn = [string]$found.Properties["distinguishedName"][0]
                                $sam = [string]$found.Properties["sAMAccountName"][0]
                                [void]$excluded.Add($dn)
                                $script:report.ExcludedAccounts.Add("$($domain.Name)\$sam")
                                Write-IdentIRLog -Message "[$($domain.Name)] Excluded account: $sam" -TypeName Info -ForegroundColor Yellow
                            }
                            $results.Dispose()
                        } catch {
                            Write-IdentIRLog -Message "[$($domain.Name)] Failed to search for excluded accounts with pattern ${pattern}: $($_.Exception.Message)" -TypeName Error -ForegroundColor Red
                            $script:report.Errors.Add("Failed to search for excluded accounts with pattern $pattern in $($domain.Name): $($_.Exception.Message)")
                        }
                        $s.Dispose()
                    }
                    if ($domain.SID) {
                        $rid500Sid = "$($domain.SID)-500"
                        $s = New-Object System.DirectoryServices.DirectorySearcher
                        $s.SearchRoot = [adsi]"LDAP://$($domain.PDC)/$($domain.DefaultNC)"
                        $s.Filter = "(objectSid=$rid500Sid)"
                        $s.PageSize = 1
                        [void]$s.PropertiesToLoad.Add("distinguishedName")
                        [void]$s.PropertiesToLoad.Add("sAMAccountName")
                        try {
                            $found = $s.FindOne()
                            if ($found) {
                                $dn = [string]$found.Properties["distinguishedName"][0]
                                $sam = [string]$found.Properties["sAMAccountName"][0]
                                if (-not $excluded.Contains($dn)) {
                                    [void]$excluded.Add($dn)
                                    $script:report.ExcludedAccounts.Add("$($domain.Name)\$sam (RID 500)")
                                    Write-IdentIRLog -Message "[$($domain.Name)] Excluded account: $sam (RID 500)" -TypeName Info -ForegroundColor Yellow
                                }
                            }
                        } catch {
                            Write-IdentIRLog -Message "[$($domain.Name)] Failed to search for RID 500 account: $($_.Exception.Message)" -TypeName Error -ForegroundColor Red
                            $script:report.Errors.Add("Failed to search for RID 500 account in $($domain.Name): $($_.Exception.Message)")
                        }
                        $s.Dispose()
                    }
                    if ($currentUserDomain -and $domain.Name -eq $currentUserDomain.Name) {
                        $s = New-Object System.DirectoryServices.DirectorySearcher
                        $s.SearchRoot = [adsi]"LDAP://$($domain.PDC)/$($domain.DefaultNC)"
                        $s.Filter = "(objectSid=$script:currentUserSid)"
                        $s.PageSize = 1
                        [void]$s.PropertiesToLoad.Add("distinguishedName")
                        [void]$s.PropertiesToLoad.Add("sAMAccountName")
                        try {
                            $found = $s.FindOne()
                            if ($found) {
                                $dn = [string]$found.Properties["distinguishedName"][0]
                                $sam = [string]$found.Properties["sAMAccountName"][0]
                                [void]$excluded.Add($dn)
                                $script:report.ExcludedAccounts.Add("$($domain.Name)\$sam (Current User)")
                                Write-IdentIRLog -Message "[$($domain.Name)] Excluded account: $sam (Current User)" -TypeName Info -ForegroundColor Yellow
                            }
                        } catch {
                            Write-IdentIRLog -Message "[$($domain.Name)] Failed to search for current user: $($_.Exception.Message)" -TypeName Error -ForegroundColor Red
                            $script:report.Errors.Add("Failed to search for current user in $($domain.Name): $($_.Exception.Message)")
                        }
                        $s.Dispose()
                    }
                } catch {
                    Write-IdentIRLog -Message "[$($domain.Name)] Failed to build exclusion list: $($_.Exception.Message)" -TypeName Error -ForegroundColor Red
                    $script:report.Errors.Add("Failed to build exclusion list for $($domain.Name): $($_.Exception.Message)")
                }
            }
            Write-IdentIRLog -Message "Excluded $($excluded.Count) accounts" -TypeName Info -ForegroundColor Yellow

            # Phase 1: Discovery of Privileged Accounts
            Write-IdentIRLog -Message "Phase 1: Discovery of Privileged Accounts" -TypeName Info -ForegroundColor Cyan
            $allPrivilegedDNs = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
            $script:privGroups = [System.Collections.Generic.List[psobject]]::new()
            foreach ($domain in $script:domains) {
                $script:report.Stats.Domains++
                $script:report.DomainsProcessed.Add($domain.Name)
                try {
                    foreach ($grpName in ($GroupNames | Sort-Object)) {
                        $isForestWide = ($ForestWideGroups -contains $grpName)
                        if ($isForestWide -and $domain.Type -ne 'Forest Root') { continue }
                        $searchSrv = if ($isForestWide) { $domain.ForestRootPDC } else { $domain.PDC }
                        $searchNC = if ($isForestWide) { $domain.ForestRootDN } else { $domain.DefaultNC }
                        $safe = Escape-LdapValue -Value $grpName
                        $flt = "(&(objectClass=group)(|(sAMAccountName=$safe)(cn=$safe)(name=$safe)))"
                        $s = New-Object System.DirectoryServices.DirectorySearcher
                        $s.SearchRoot = [adsi]"LDAP://$searchSrv/$searchNC"
                        $s.Filter = $flt
                        [void]$s.PropertiesToLoad.Add("distinguishedName")
                        [void]$s.PropertiesToLoad.Add("sAMAccountName")
                        try {
                            $found = $s.FindOne()
                            if ($found) {
                                $grpDN = [string]$found.Properties["distinguishedName"][0]
                                $grpSam = [string]$found.Properties["sAMAccountName"][0]
                                $script:report.Stats.Groups++
                                $script:report.GroupsProcessed.Add("$($domain.Name)\$grpSam")
                                $script:privGroups.Add([PSCustomObject]@{
                                    Domain=$domain.Name; Sam=$grpSam; DN=$grpDN
                                    Server=$searchSrv; NC=$searchNC; Type=$domain.Type
                                    DomainSID=$domain.SID; ForestRootSID=$domain.ForestRootSID
                                })
                                Write-IdentIRLog -Message "[$($domain.Name)] Found group: $grpSam" -TypeName Info -ForegroundColor Yellow
                                $members = Get-NestedGroupMembers -GroupDN $grpDN -Server $searchSrv
                                foreach ($mem in ($members | Sort-Object SamAccountName)) {
                                    if ($excluded.Contains($mem.DN)) { continue }
                                    try {
                                        $obj = [adsi]"LDAP://$searchSrv/$($mem.DN)"
                                        $oc = $obj.Properties["objectClass"]
                                        $isUser = ($oc -contains "user") -and (-not ($oc -contains "computer"))
                                        if ($isUser) {
                                            [void]$allPrivilegedDNs.Add($mem.DN)
                                            Write-IdentIRLog -Message "[$($domain.Name)] Privileged member: $($mem.SamAccountName) in $grpSam" -TypeName Info -ForegroundColor White
                                        }
                                    } catch {
                                        Write-IdentIRLog -Message "[$($domain.Name)] Failed to check objectClass for $($mem.DN): $($_.Exception.Message)" -TypeName Error -ForegroundColor Red
                                        $script:report.Errors.Add("Failed to check objectClass for $($mem.DN) in $($domain.Name): $($_.Exception.Message)")
                                    }
                                }
                            }
                        } catch {
                            Write-IdentIRLog -Message "[$($domain.Name)] Failed to search for group ${grpName}: $($_.Exception.Message)" -TypeName Error -ForegroundColor Red
                            $script:report.Errors.Add("Failed to search for group $grpName in $($domain.Name): $($_.Exception.Message)")
                        }
                        $s.Dispose()
                    }
                } catch {
                    Write-IdentIRLog -Message "[$($domain.Name)] Error scanning groups: $($_.Exception.Message)" -TypeName Error -ForegroundColor Red
                    $script:report.Errors.Add("Error scanning groups for $($domain.Name): $($_.Exception.Message)")
                }
            }
            $sortedUsers = @($allPrivilegedDNs | Sort-Object)
            $script:report.Stats.PrivilegedUsers = $sortedUsers.Count
            Write-IdentIRLog -Message "Discovered $($sortedUsers.Count) Privileged Accounts" -TypeName Info -ForegroundColor Green

            # Phase 2: Privileged Accounts Disposition
            Write-IdentIRLog -Message "Phase 2: Privileged Accounts Disposition" -TypeName Info -ForegroundColor Cyan
            $sortedUsersWithDetails = @()
            foreach ($objDN in $sortedUsers) {
                try {
                    $srv = Get-ServerForDN -DN $objDN -Contexts $script:domains -Fallback $script:ForestContext.RootPDC
                    $dom = Get-DomainFromDN -DN $objDN
                    $obj = [adsi]"LDAP://$srv/$objDN"
                    if (-not $obj.Properties) { continue }
                    $oc = $obj.Properties["objectClass"]
                    $isComputer = ($oc -contains "computer")
                    $isUser = ($oc -contains "user") -and (-not $isComputer)
                    if (-not $isUser) { continue }
                    $sam = if ($obj.Properties.Contains("sAMAccountName")) { [string]$obj.Properties["sAMAccountName"].Value } else { "Unknown" }
                    $script:report.PrivilegedUsers.Add([PSCustomObject]@{ Domain=$dom; SAM=$sam; DN=$objDN; Type="User" })
                    $sortedUsersWithDetails += [PSCustomObject]@{
                        DN = $objDN
                        Domain = $dom
                        SamAccountName = $sam
                        DomainType = ($script:domains | Where-Object { $_.Name -eq $dom }).Type
                    }
                } catch {
                    Write-IdentIRLog -Message "Failed to retrieve details for ${objDN}: $($_.Exception.Message)" -TypeName Error -ForegroundColor Red
                    $script:report.Errors.Add("Failed to retrieve details for ${objDN}: $($_.Exception.Message)")
                }
            }

            foreach ($user in ($sortedUsersWithDetails | Sort-Object @{ Expression = { $priority[$_.DomainType] } }, Domain, SamAccountName)) {
                try {
                    $objDN = $user.DN
                    $dom = $user.Domain
                    $sam = $user.SamAccountName
                    $srv = Get-ServerForDN -DN $objDN -Contexts $script:domains -Fallback $script:ForestContext.RootPDC
                    $obj = [adsi]"LDAP://$srv/$objDN"
                    $sidVal = $null
                    try { $sidVal = (New-Object System.Security.Principal.SecurityIdentifier($obj.Properties["objectSid"].Value,0)).Value } catch {}
                    if ($sidVal) {
                        if ($sidVal -match '-500$') { continue }
                        if ($sidVal -eq $script:currentUserSid) { continue }
                    }
                    if ($isWhatIf) {
                        $obj.RefreshCache()
                        $uac = [int]$obj.Properties['userAccountControl'].Value
                        $actions = @()
                        if (($uac -band 0x2) -eq 0) { $actions += "Disable account"; $script:report.Stats.AccountsDisabled++ }
                        if (($uac -band 0x10000) -ne 0) { $actions += "Remove password never expires"; $script:report.Stats.PasswordNeverExpiresRemoved++ }
                        if (($uac -band 0x40000) -eq 0) { $actions += "Require smart card"; $script:report.Stats.SmartCardRequired++ }
                        if (($uac -band 0x400000) -ne 0) { $actions += "Remove preauth"; $script:report.Stats.PreauthRemoved++ }
                        if (($uac -band 0x100000) -eq 0) { $actions += "Set not delegated"; $script:report.Stats.NotDelegatedSet++ }
                        $script:report.Stats.PasswordsReset++
                        $defaultPrimary = 513
                        $primaryGroupID = if ($obj.Properties.Contains('primaryGroupID')) { [int]$obj.Properties['primaryGroupID'].Value } else { $null }
                        if ($primaryGroupID -and $primaryGroupID -ne $defaultPrimary) {
                            $actions += "Fix primary group"
                            $script:report.Stats.PrimaryGroupFixed++
                        }
                        Write-IdentIRLog -Message "[WHATIF] [$dom] Would process privileged user $sam ($($actions -join ', '))" -TypeName Info -ForegroundColor White
                        continue
                    }
                    $obj.RefreshCache()
                    $uac = [int]$obj.Properties['userAccountControl'].Value
                    $pre = $uac
                    if (($uac -band 0x2) -eq 0) { $uac = $uac -bor 0x2 }
                    if (($uac -band 0x10000) -ne 0) { $uac = $uac -band (-bnot 0x10000) }
                    if (($uac -band 0x40000) -eq 0) { $uac = $uac -bor 0x40000 }
                    if (($uac -band 0x400000) -ne 0) { $uac = $uac -band (-bnot 0x400000) }
                    if (($uac -band 0x100000) -eq 0) { $uac = $uac -bor 0x100000 }
                    if ($uac -ne $pre) {
                        try {
                            $obj.Properties['userAccountControl'].Value = $uac
                            $obj.CommitChanges()
                            if (($pre -band 0x2) -eq 0) { $script:report.AccountsDisabled.Add("$dom\$sam"); $script:report.Stats.AccountsDisabled++ }
                            if (($pre -band 0x10000) -ne 0) { $script:report.PasswordNeverExpiresRemoved.Add("$dom\$sam"); $script:report.Stats.PasswordNeverExpiresRemoved++ }
                            if (($pre -band 0x40000) -eq 0) { $script:report.SmartCardRequired.Add("$dom\$sam"); $script:report.Stats.SmartCardRequired++ }
                            if (($pre -band 0x400000) -ne 0) { $script:report.PreauthRemoved.Add("$dom\$sam"); $script:report.Stats.PreauthRemoved++ }
                            if (($pre -band 0x100000) -eq 0) { $script:report.NotDelegatedSet.Add("$dom\$sam"); $script:report.Stats.NotDelegatedSet++ }
                            Write-IdentIRLog -Message "[$dom] Updated UAC for $sam" -TypeName Info -ForegroundColor Green
                        } catch {
                            Write-IdentIRLog -Message "[$dom] UAC update failed for ${sam}: $($_.Exception.Message)" -TypeName Error -ForegroundColor Red
                            $script:report.Errors.Add("UAC update failed for $dom\${sam}: $($_.Exception.Message)")
                        }
                    }
                    try {
                        $p1 = New-Password -Length 24
                        $obj.SetPassword($p1)
                        Start-Sleep -Milliseconds 500
                        $p2 = New-Password -Length 24
                        $obj.SetPassword($p2)
                        $script:report.PasswordsReset.Add("$dom\$sam")
                        $script:report.Stats.PasswordsReset++
                        Write-IdentIRLog -Message "[$dom] Reset password for $sam" -TypeName Info -ForegroundColor Green
                    } catch {
                        Write-IdentIRLog -Message "[$dom] Password reset failed for ${sam}: $($_.Exception.Message)" -TypeName Error -ForegroundColor Red
                        $script:report.Errors.Add("Password reset failed for $dom\${sam}: $($_.Exception.Message)")
                    }
                    $obj.RefreshCache()
                    $defaultPrimary = 513
                    $primaryGroupID = if ($obj.Properties.Contains('primaryGroupID')) { [string]$obj.Properties['primaryGroupID'].Value } else { $null }
                    if ($primaryGroupID -and $primaryGroupID -ne $defaultPrimary) {
                        try {
                            $obj.Properties['primaryGroupID'].Value = $defaultPrimary
                            $obj.CommitChanges()
                            $script:report.PrimaryGroupFixed.Add("$dom\$sam")
                            $script:report.Stats.PrimaryGroupFixed++
                            Write-IdentIRLog -Message "[$dom] Fixed primary group for $sam" -TypeName Info -ForegroundColor Green
                        } catch {
                            Write-IdentIRLog -Message "[$dom] Primary group update failed for ${sam}: $($_.Exception.Message)" -TypeName Error -ForegroundColor Red
                            $script:report.Errors.Add("Primary group update failed for $dom\${sam}: $($_.Exception.Message)")
                        }
                    }
                } catch {
                    Write-IdentIRLog -Message "Failed to process ${objDN}: $($_.Exception.Message)" -TypeName Error -ForegroundColor Red
                    $script:report.Errors.Add("Failed to process ${objDN}: $($_.Exception.Message)")
                }
            }
            Write-IdentIRLog -Message "Privileged Accounts Disposition Complete" -TypeName Info -ForegroundColor Green

            # Phase 3: Group Cleanup
            Write-IdentIRLog -Message "Phase 3: Group Cleanup" -TypeName Info -ForegroundColor Cyan
            $totalRemoved = 0
            foreach ($pgrp in ($script:privGroups | Sort-Object @{ Expression = { $priority[$_.Type] } }, Sam)) {
                try {
                    $grp = [adsi]"LDAP://$($pgrp.Server)/$($pgrp.DN)"
                    $members = @($grp.Properties['member'] | Where-Object { $_ -notlike '*CN=ForeignSecurityPrincipals,*' })
                    $domain = $script:domains | Where-Object { $_.Name -eq $pgrp.Domain } | Select-Object -First 1
                    if (-not $domain) { $domain = $script:domains | Select-Object -First 1 }
                    $defaultMems = Get-DefaultGroupMemberships `
                        -GroupName $pgrp.Sam `
                        -DomainType $pgrp.Type `
                        -DomainSID $pgrp.DomainSID `
                        -ForestRootSID $pgrp.ForestRootSID `
                        -Server $pgrp.Server `
                        -SearchBase $pgrp.NC `
                        -ForestRootDN $domain.ForestRootDN
                    $defaultSet = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
                    $null = $defaultMems | ForEach-Object { [void]$defaultSet.Add($_.DN) }
                    if ($pgrp.Sam -ieq 'Denied RODC Password Replication Group') {
                        $protectRidsDomain = 512,516,517,520,521
                        foreach ($rid in $protectRidsDomain) {
                            $result = Get-DNByRid -DomainSid $pgrp.DomainSID -Server $pgrp.Server -SearchBase $pgrp.NC -Rid $rid
                            if ($result) { [void]$defaultSet.Add($result.DN) }
                        }
                        $protectRidsForest = 518,519
                        foreach ($rid in $protectRidsForest) {
                            $result = Get-DNByRid -DomainSid $pgrp.ForestRootSID -Server $pgrp.Server -SearchBase $domain.ForestRootDN -Rid $rid
                            if ($result) { [void]$defaultSet.Add($result.DN) }
                        }
                    }
                    $removedCount = 0
                    Write-IdentIRLog -Message "[$($pgrp.Domain)] Processing group: $($pgrp.Sam)" -TypeName Info -ForegroundColor White
                    foreach ($memDN in $members) {
                        if ($defaultSet.Contains($memDN)) { continue }
                        if ($excluded.Contains($memDN)) { continue }
                        $isRid500 = $false
                        try {
                            $sidBytes = ([adsi]"LDAP://$($pgrp.Server)/$memDN").Properties['objectSid'].Value
                            if ($sidBytes) {
                                $sidVal = (New-Object System.Security.Principal.SecurityIdentifier($sidBytes,0)).Value
                                if ($sidVal -match '-500$') { $isRid500 = $true }
                            }
                        } catch {
                            Write-IdentIRLog -Message "[$($pgrp.Domain)] Failed to check SID for $memDN in $($pgrp.Sam): $($_.Exception.Message)" -TypeName Error -ForegroundColor Red
                            $script:report.Errors.Add("Failed to check SID for $memDN in $($pgrp.Domain)\$($pgrp.Sam): $($_.Exception.Message)")
                        }
                        if ($isRid500) { continue }
                        try {
                            $memObj = [adsi]"LDAP://$($pgrp.Server)/$memDN"
                            $memSam = if ($memObj.Properties.Contains("sAMAccountName")) { [string]$memObj.Properties["sAMAccountName"].Value } else { "Unknown" }
                            if ($isWhatIf) {
                                Write-IdentIRLog -Message "[WHATIF] [$($pgrp.Domain)] Would remove $memSam from $($pgrp.Sam)" -TypeName Info -ForegroundColor White
                                $removedCount++
                            } else {
                                $grp.Properties['member'].Remove($memDN)
                                $grp.CommitChanges()
                                $removedCount++
                                Write-IdentIRLog -Message "[$($pgrp.Domain)] Removed $memSam from $($pgrp.Sam)" -TypeName Info -ForegroundColor Green
                            }
                        } catch {
                            Write-IdentIRLog -Message "[$($pgrp.Domain)] Failed to remove $memDN from $($pgrp.Sam): $($_.Exception.Message)" -TypeName Error -ForegroundColor Red
                            $script:report.Errors.Add("Failed to remove $memDN from $($pgrp.Domain)\$($pgrp.Sam): $($_.Exception.Message)")
                        }
                    }
                    $totalRemoved += $removedCount
                    if ($removedCount -gt 0) {
                        $script:report.MembershipsRevoked.Add("$($pgrp.Domain)\$($pgrp.Sam) ($removedCount)")
                        $script:report.Stats.MembershipsRevoked += $removedCount
                    }
                } catch {
                    Write-IdentIRLog -Message "[$($pgrp.Domain)] Failed to process group $($pgrp.Sam): $($_.Exception.Message)" -TypeName Error -ForegroundColor Red
                    $script:report.Errors.Add("Failed to process group $($pgrp.Domain)\$($pgrp.Sam): $($_.Exception.Message)")
                }
            }
            Write-IdentIRLog -Message "Group cleanup complete - removed $totalRemoved" -TypeName Info -ForegroundColor Green

            # Phase 4: Container ACL Reset
            Write-IdentIRLog -Message "Phase 4: Container ACL Reset" -TypeName Info -ForegroundColor Cyan
            foreach ($domain in $script:domains) {
                if (-not $domain.SID -or -not $domain.ForestRootSID) { continue }
                $containers = @(
                    @{ DN = $domain.DefaultNC; Name = 'Domain Root'; BaselineKey = 'DomainRoot' }
                    @{ DN = "OU=Domain Controllers,$($domain.DefaultNC)"; Name = 'Domain Controllers'; BaselineKey = 'DomainControllersOU' }
                    @{ DN = "CN=AdminSDHolder,CN=System,$($domain.DefaultNC)"; Name = 'Admin SD Holder'; BaselineKey = 'AdminSDHolder' }
                )
                foreach ($cont in ($containers | Sort-Object Name)) {
                    try {
                        $contObj = [adsi]"LDAP://$($domain.PDC)/$($cont.DN)"
                        if (-not $contObj.Properties) {
                            Write-IdentIRLog -Message "[$($domain.Name)] Container $($cont.Name) not found" -TypeName Warning -ForegroundColor Yellow
                            $script:report.Errors.Add("Container $($domain.Name)\$($cont.Name) not found")
                            continue
                        }
                        $baseline = Get-CleanSDDL -DomainType $domain.Type -ContainerType $cont.BaselineKey -ForestRootSID $domain.ForestRootSID -DomainSID $domain.SID
                        $baselineSddl = $baseline.SDDL
                        $baselineInheritanceBlocked = $baseline.InheritanceBlocked
                        $comparison = Compare-SddlToClean -ADObject $contObj -CleanSDDL $baselineSddl -BaselineInheritanceBlocked $baselineInheritanceBlocked -ContainerName "$($domain.Name)\$($cont.Name)"
                        $script:report.ContainerComparisons.Add([PSCustomObject]@{
                            Domain = $domain.Name; DomainType = $domain.Type; Container = $cont.Name
                            DaclMatch = $comparison.DaclMatch; InheritanceMatch = $comparison.InheritanceMatch
                            NeedsChange = $comparison.NeedsChange; Adds=$comparison.Adds; Removes=$comparison.Removes
                        })
                        if (-not $comparison.NeedsChange) { continue }
                        if ($isWhatIf) {
                            $script:report.Stats.ContainerAclsNeedingReset++
                            continue
                        }
                        $allowInheritance = -not $baselineInheritanceBlocked
                        $ok = Reset-ObjectAcl -ADObject $contObj -CleanSD $comparison.CleanSD -RemoveAdminCount:$false -AllowInheritance:$allowInheritance -AccessOnly
                        if ($ok) {
                            $script:report.ContainerAclsReset.Add("$($domain.Name)\$($cont.Name)")
                            $script:report.Stats.ContainerAclsReset++
                        }
                    } catch {
                        Write-IdentIRLog -Message "[$($domain.Name)] Error processing $($cont.Name): $($_.Exception.Message)" -TypeName Error -ForegroundColor Red
                        $script:report.Errors.Add("Error processing $($domain.Name)\$($cont.Name): $($_.Exception.Message)")
                    }
                }
            }
            Write-IdentIRLog -Message "Container ACL Reset Complete" -TypeName Info -ForegroundColor Green

            # Phase 5: Orphan Admin Account Cleanup
            Write-IdentIRLog -Message "Phase 5: Orphan Admin Account Cleanup" -TypeName Info -ForegroundColor Cyan
            foreach ($domain in $script:domains) {
                try {
                    $searcher = New-Object System.DirectoryServices.DirectorySearcher
                    $searcher.SearchRoot = [adsi]"LDAP://$($domain.PDC)/$($domain.DefaultNC)"
                    # CRITICAL: Only target user objects with adminCount=1
                    $searcher.Filter = "(&(objectClass=user)(objectCategory=person)(adminCount=1))"
                    $searcher.PageSize = 1000
                    [void]$searcher.PropertiesToLoad.Add("distinguishedName")
                    [void]$searcher.PropertiesToLoad.Add("sAMAccountName")
                    [void]$searcher.PropertiesToLoad.Add("objectClass")
                    try {
                        $results = $searcher.FindAll()
                        $adminCountObjects = @()
                        foreach ($result in $results) {
                            $dn = [string]$result.Properties["distinguishedName"][0]
                            $sam = if ($result.Properties["sAMAccountName"] -and $result.Properties["sAMAccountName"][0]) { [string]$result.Properties["sAMAccountName"][0] } else { "Unknown" }
                            $adminCountObjects += [PSCustomObject]@{
                                DN = $dn
                                SamAccountName = $sam
                                Domain = $domain.Name
                                DomainType = $domain.Type
                            }
                        }
                        $results.Dispose()
                        foreach ($obj in ($adminCountObjects | Sort-Object @{ Expression = { $priority[$_.DomainType] } }, SamAccountName)) {
                            try {
                                if ($excluded.Contains($obj.DN)) { continue }
                                $adObj = [adsi]"LDAP://$($domain.PDC)/$($obj.DN)"
                                if ($isWhatIf) {
                                    if ($adObj.Properties.Contains('adminCount') -and $adObj.Properties['adminCount'].Value -eq 1) {
                                        Write-IdentIRLog -Message "[WHATIF] [$($obj.Domain)] Would clear adminCount for $($obj.SamAccountName)" -TypeName Info -ForegroundColor White
                                        $script:report.Stats.PerObjectAclsNeedingReset++
                                    }
                                    if ($adObj.psbase.ObjectSecurity.AreAccessRulesProtected) {
                                        Write-IdentIRLog -Message "[WHATIF] [$($obj.Domain)] Would enable inheritance for $($obj.SamAccountName)" -TypeName Info -ForegroundColor White
                                        $script:report.Stats.PerObjectAclsNeedingReset++
                                    }
                                    continue
                                }
                                $inheritanceBlocked = $adObj.psbase.ObjectSecurity.AreAccessRulesProtected
                                $hasAdminCount = $adObj.Properties.Contains('adminCount') -and $adObj.Properties['adminCount'].Value -eq 1
                                if ($hasAdminCount -or $inheritanceBlocked) {
                                    if ($hasAdminCount) {
                                        $adObj.Properties['adminCount'].Clear()
                                        Write-IdentIRLog -Message "[$($obj.Domain)] Cleared adminCount for $($obj.SamAccountName)" -TypeName Info -ForegroundColor Green
                                    }
                                    if ($inheritanceBlocked) {
                                        $adObj.psbase.ObjectSecurity.SetAccessRuleProtection($false, $true)
                                        Write-IdentIRLog -Message "[$($obj.Domain)] Enabled inheritance for $($obj.SamAccountName)" -TypeName Info -ForegroundColor Green
                                    }
                                    $adObj.CommitChanges()
                                    $script:report.AclsReset.Add("$($obj.Domain)\$($obj.SamAccountName) ($($obj.DN))")
                                    $script:report.Stats.AclsReset++
                                }
                            } catch {
                                Write-IdentIRLog -Message "[$($obj.Domain)] Failed to process $($obj.DN): $($_.Exception.Message)" -TypeName Error -ForegroundColor Red
                                $script:report.Errors.Add("Failed to process $($obj.DN) in $($obj.Domain): $($_.Exception.Message)")
                            }
                        }
                    } catch {
                        Write-IdentIRLog -Message "[$($domain.Name)] Failed to search adminCount=1: $($_.Exception.Message)" -TypeName Error -ForegroundColor Red
                        $script:report.Errors.Add("Failed to search adminCount=1 in $($domain.Name): $($_.Exception.Message)")
                    }
                    $searcher.Dispose()
                } catch {
                    Write-IdentIRLog -Message "[$($domain.Name)] Failed to initialize search for adminCount=1: $($_.Exception.Message)" -TypeName Error -ForegroundColor Red
                    $script:report.Errors.Add("Failed to initialize search for adminCount=1 in $($domain.Name): $($_.Exception.Message)")
                }
            }
            Write-IdentIRLog -Message "Orphan Admin Account Cleanup Complete" -TypeName Info -ForegroundColor Green

            # Phase 6: Trigger SDProp
            if ($script:report.Stats.ContainerAclsReset -gt 0 -or $script:report.Stats.MembershipsRevoked -gt 0) {
                Write-IdentIRLog -Message "Phase 6: Trigger SDProp" -TypeName Info -ForegroundColor Cyan
                if ($isWhatIf) {
                    Write-IdentIRLog -Message "[WHATIF] Would trigger SDProp" -TypeName Info -ForegroundColor White
                } else {
                    foreach ($domain in $script:domains) {
                        try {
                            $rootDSE = [adsi]"LDAP://$($domain.PDC)/RootDSE"
                            $rootDSE.Properties['runProtectAdminGroupsTask'].Value = 1
                            $rootDSE.CommitChanges()
                            Write-IdentIRLog -Message "[$($domain.Name)] Triggered SDProp" -TypeName Info -ForegroundColor Green
                        } catch {
                            Write-IdentIRLog -Message "[$($domain.Name)] SDProp failed: $($_.Exception.Message)" -TypeName Error -ForegroundColor Red
                            $script:report.Errors.Add("SDProp failed for $($domain.Name): $($_.Exception.Message)")
                        }
                    }
                }
            }

            # Summary
            $script:report.EndTime = Get-Date
            Write-IdentIRLog -Message "================================================" -TypeName Info -ForegroundColor White
            Write-IdentIRLog -Message "SUMMARY" -TypeName Info -ForegroundColor Cyan
            Write-IdentIRLog -Message "================================================" -TypeName Info -ForegroundColor White
            Write-IdentIRLog -Message " Domains: $($script:report.Stats.Domains)" -TypeName Info -ForegroundColor White
            Write-IdentIRLog -Message " Groups scanned: $($script:report.Stats.Groups)" -TypeName Info -ForegroundColor White
            Write-IdentIRLog -Message " Privileged principals found: $($script:report.Stats.PrivilegedUsers)" -TypeName Info -ForegroundColor Cyan
            Write-IdentIRLog -Message " Excluded accounts: $($script:report.ExcludedAccounts.Count)" -TypeName Info -ForegroundColor Yellow
            if ($isWhatIf) {
                Write-IdentIRLog -Message " Group removals (simulated): $($script:report.Stats.MembershipsRevoked)" -TypeName Info -ForegroundColor White
                Write-IdentIRLog -Message " Container ACLs needing reset (simulated): $($script:report.Stats.ContainerAclsNeedingReset)" -TypeName Info -ForegroundColor White
                Write-IdentIRLog -Message " Per-object fixes (simulated): $($script:report.Stats.PerObjectAclsNeedingReset)" -TypeName Info -ForegroundColor White
                Write-IdentIRLog -Message " Accounts to disable (simulated): $($script:report.Stats.AccountsDisabled)" -TypeName Info -ForegroundColor White
                Write-IdentIRLog -Message " Password never expires to remove (simulated): $($script:report.Stats.PasswordNeverExpiresRemoved)" -TypeName Info -ForegroundColor White
                Write-IdentIRLog -Message " Smart card to require (simulated): $($script:report.Stats.SmartCardRequired)" -TypeName Info -ForegroundColor White
                Write-IdentIRLog -Message " Preauth to remove (simulated): $($script:report.Stats.PreauthRemoved)" -TypeName Info -ForegroundColor White
                Write-IdentIRLog -Message " Not delegated to set (simulated): $($script:report.Stats.NotDelegatedSet)" -TypeName Info -ForegroundColor White
                Write-IdentIRLog -Message " Passwords to reset (simulated): $($script:report.Stats.PasswordsReset)" -TypeName Info -ForegroundColor White
                Write-IdentIRLog -Message " Primary group to fix (simulated): $($script:report.Stats.PrimaryGroupFixed)" -TypeName Info -ForegroundColor White
            } else {
                Write-IdentIRLog -Message " Group removals: $($script:report.Stats.MembershipsRevoked)" -TypeName Info -ForegroundColor White
                Write-IdentIRLog -Message " Container ACLs reset: $($script:report.Stats.ContainerAclsReset)" -TypeName Info -ForegroundColor White
                Write-IdentIRLog -Message " Per-object fixes: $($script:report.Stats.AclsReset)" -TypeName Info -ForegroundColor White
                Write-IdentIRLog -Message " Accounts disabled: $($script:report.Stats.AccountsDisabled)" -TypeName Info -ForegroundColor White
                Write-IdentIRLog -Message " Password never expires removed: $($script:report.Stats.PasswordNeverExpiresRemoved)" -TypeName Info -ForegroundColor White
                Write-IdentIRLog -Message " Smart card required: $($script:report.Stats.SmartCardRequired)" -TypeName Info -ForegroundColor White
                Write-IdentIRLog -Message " Preauth removed: $($script:report.Stats.PreauthRemoved)" -TypeName Info -ForegroundColor White
                Write-IdentIRLog -Message " Not delegated set: $($script:report.Stats.NotDelegatedSet)" -TypeName Info -ForegroundColor White
                Write-IdentIRLog -Message " Passwords reset: $($script:report.Stats.PasswordsReset)" -TypeName Info -ForegroundColor White
                Write-IdentIRLog -Message " Primary group fixed: $($script:report.Stats.PrimaryGroupFixed)" -TypeName Info -ForegroundColor White
            }
            Write-IdentIRLog -Message " Errors: $($script:report.Errors.Count)" -TypeName Info -ForegroundColor $(if ($script:report.Errors.Count -gt 0) { 'Red' } else { 'White' })
            if ($script:report.Errors.Count -gt 0) {
                Write-IdentIRLog -Message "Error Details:" -TypeName Info -ForegroundColor Red
                foreach ($error in ($script:report.Errors | Sort-Object)) {
                    Write-IdentIRLog -Message $error -TypeName Error -ForegroundColor Red
                }
            }
            Write-IdentIRLog -Message " Duration: $([math]::Round(($script:report.EndTime - $script:report.StartTime).TotalSeconds, 2))s" -TypeName Info -ForegroundColor White
            Write-IdentIRLog -Message "================================================" -TypeName Info -ForegroundColor White
            return $script:report
        }
     }
