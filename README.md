# TargetedTimeroast
PoC to tamper Active Directory user attributes to collect their hashes with MS-SNTP.

![timeroast](https://github.com/user-attachments/assets/c8b475fa-37fc-41b7-8676-228e75a057f5)

Read [this article](https://medium.com/@offsecdeer/targeted-timeroasting-stealing-user-hashes-with-ntp-b75c1f71b9ac) for the full description of the attack. This script requires:
- domain admin credentials
- domain joined machine
- AD PS module installed

The script targets either a single user (`-victim`) or a list of users (`-file`), in both cases users are specified by `sAMAccountName`. Show verbose output with `-v`. Write hashes to a file with `-outputFile`

The PoC temporarily modifies each target's `userAccountControl` and `sAMAccountName` attributes so that an MD5 digest calculated from their NT hash can be retrieved with MS-SNTP, aka via "timeroasting". Attributes are then restored to original values.

This is a modified version of Jacopo Scannella's original [PowerShell timeroast script](https://github.com/SecuraBV/Timeroast/blob/main/timeroast.ps1). It's a very poorly made PoC written by someone who doesn't have much knowledge of PowerShell in general, so I don't recommend using it in production environments.

Keep in mind that if for some reason users get stuck with the modified `userAccountControl` value they will be unable to logon interactively until `UF_WORKSTATION_TRUST_ACCOUNT` has been replaced by `UF_NORMAL_ACCOUNT`. The script cleans up after itself but you never know.
