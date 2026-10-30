# net.exe Account Manipulation — Detection Guide

How attackers and admins create, delete and change group membership of accounts with `net.exe`,
what the command line **always** contains, and how the Sigma rules in this repo catch it.

## What is always present
| Action | Process | Command line must contain | Confirming Windows event ID |
|---|---|---|---|
| Add user | net.exe / net1.exe | user + /add | 4720 |
| Delete user | net.exe / net1.exe | user + /del | 4726 |
| Add group member | net.exe / net1.exe | group + /add | 4732 (local), 4728 (global), 4756 (universal) |
| Remove group member | net.exe / net1.exe | group + /del | 4733 (local), 4729 (global), 4757 (universal) |

- `net.exe` usually spawns `net1.exe` with the same arguments — expect two process events per action and deduplicate.
- `group` matches both `localgroup` and `group`; `/del` matches `/del` and `/delete`.
- The **child** net.exe command line is always clean, even if the parent `cmd.exe` used caret (`^`) obfuscation.
- Check `OriginalFileName` so renamed copies of net.exe are still caught.
- Process events need Sysmon Event 1, or Security 4688 with command-line logging enabled.

## User add / delete variations
| Variation | Add user | Delete user |
|---|---|---|
| Standard | `net user bob P@ss123 /add` | `net user bob /delete` |
| Short switch | `net user bob P@ss123 /add (already short)` | `net user bob /del` |
| No password given | `net user bob /add (blank password)` | n/a |
| Prompt for password | `net user bob * /add` | n/a |
| Domain account | `net user bob P@ss123 /add /domain` | `net user bob /delete /domain` |
| Domain, short | `net user bob P@ss123 /add /dom` | `net user bob /del /dom` |
| Plural subcommand | `net users bob P@ss123 /add` | `net users bob /delete` |
| Switch before name | `net user /add bob P@ss123` | `net user /del bob` |
| Extra options | `net user bob P@ss123 /add /active:yes /expires:never /passwordchg:no` | n/a |
| Hidden-looking name | `net user admin$ P@ss123 /add  ($ hides it from some listings)` | `net user admin$ /del` |
| Look-alike name | `net user Adminstrator P@ss123 /add ; net user svc_backup ... /add` | `net user Adminstrator /del` |
| Name with spaces | `net user "Help Desk" P@ss123 /add` | `net user "Help Desk" /delete` |
| Upper or mixed case | `NET USER bob P@ss123 /ADD` | `NeT uSeR bob /DeL` |
| Full path | `C:\Windows\System32\net.exe user bob P@ss123 /add` | `C:\Windows\System32\net.exe user bob /delete` |
| 32-bit path | `C:\Windows\SysWOW64\net.exe user bob P@ss123 /add` | `C:\Windows\SysWOW64\net.exe user bob /del` |
| net1 directly | `net1 user bob P@ss123 /add` | `net1 user bob /delete` |
| Extra spaces | `net   user  bob  P@ss123   /add` | `net   user   bob    /delete` |
| Via cmd | `cmd.exe /c net user bob P@ss123 /add` | `cmd.exe /c net user bob /delete` |
| Caret obfuscation (parent cmd only) | `cmd /c n^et us^er bob P@ss123 /a^dd` | `cmd /c n^e^t u^s^e^r bob /d^el` |
| Via PowerShell | `powershell -c "net user bob P@ss123 /add"` | `powershell -c "net user bob /delete"` |
| Loop or mass action | `for %u in (a b c) do net user %u P@ss123 /add` | `for %u in (a b c) do net user %u /del` |
| Remote via PsExec or WMI | `psexec \\host net user bob P@ss123 /add` | `wmic /node:host process call create "net user bob /del"` |
| Renamed binary | `C:\Temp\x.exe user bob P@ss123 /add` | `C:\Temp\x.exe user bob /delete` |

## Group membership add / remove variations
| Variation | Add member | Remove member |
|---|---|---|
| Local admin | `net localgroup administrators bob /add` | `net localgroup administrators bob /delete` |
| Short switch | `net localgroup administrators bob /add (already short)` | `net localgroup administrators bob /del` |
| RDP access | `net localgroup "Remote Desktop Users" bob /add` | `net localgroup "Remote Desktop Users" bob /del` |
| Domain group | `net group "Domain Admins" bob /add /domain` | `net group "Domain Admins" bob /delete /domain` |
| Domain, short | `net group "Domain Admins" bob /add /dom` | `net group "Domain Admins" bob /del /dom` |
| Domain user into local group | `net localgroup administrators CORP\bob /add` | `net localgroup administrators CORP\bob /del` |
| Switch before names | `net localgroup /add administrators bob` | `net localgroup /del administrators bob` |
| Multiple users | `net localgroup administrators bob alice /add` | `net localgroup administrators bob alice /del` |
| Localized group names | `net localgroup Administratoren bob /add  (German); Administrateurs (French); Administradores (Spanish)` | Same names with /del |
| Upper or mixed case | `NET LOCALGROUP Administrators bob /ADD` | `NeT LoCaLgRoUp administrators bob /DeL` |
| Full path | `C:\Windows\System32\net.exe localgroup administrators bob /add` | `C:\Windows\System32\net.exe localgroup administrators bob /del` |
| 32-bit path | `C:\Windows\SysWOW64\net.exe localgroup administrators bob /add` | `C:\Windows\SysWOW64\net.exe localgroup administrators bob /del` |
| net1 directly | `net1 localgroup administrators bob /add` | `net1 localgroup administrators bob /del` |
| Via cmd | `cmd.exe /c net localgroup administrators bob /add` | `cmd.exe /c net localgroup administrators bob /del` |
| Caret obfuscation (parent cmd only) | `cmd /c n^et loc^algroup admin^istrators bob /a^dd` | `cmd /c n^et loc^algroup admin^istrators bob /d^el` |
| Via PowerShell | `powershell -c "net localgroup administrators bob /add"` | `powershell -c "net localgroup administrators bob /del"` |
| Remote via PsExec | `psexec \\host net localgroup administrators bob /add` | `psexec \\host net localgroup administrators bob /del` |
| Renamed binary | `C:\Temp\x.exe localgroup administrators bob /add` | `C:\Temp\x.exe localgroup administrators bob /del` |

## Common attack chains
| Chain | Commands | Why it matters |
|---|---|---|
| Backdoor admin | `net user bob P@ss123 /add && net localgroup administrators bob /add` | Account created then immediately made local admin |
| Backdoor with RDP | `Backdoor admin chain + net localgroup "Remote Desktop Users" bob /add` | Gives the attacker interactive remote access |
| Lock out defenders | `net user itadmin /del ; net localgroup administrators itadmin /del` | Ransomware / wiper behavior - removes real admins |
| Cover tracks | `net user bob ... /add  ->  (activity)  ->  net user bob /del minutes later` | Short-lived account is a strong signal |

## Rules in this repo
| Rule | Detects |
|---|---|
| [`proc_creation_win_net_user_add.yml`](../rules/windows/process_creation/proc_creation_win_net_user_add.yml) | `net user ... /add` |
| [`proc_creation_win_net_user_delete.yml`](../rules/windows/process_creation/proc_creation_win_net_user_delete.yml) | `net user ... /del` |
| [`proc_creation_win_net_group_member_add.yml`](../rules/windows/process_creation/proc_creation_win_net_group_member_add.yml) | `net localgroup/group ... /add` |
| [`proc_creation_win_net_group_member_add_privileged.yml`](../rules/windows/process_creation/proc_creation_win_net_group_member_add_privileged.yml) | Same, privileged groups only (high) |
| [`proc_creation_win_net_group_member_remove.yml`](../rules/windows/process_creation/proc_creation_win_net_group_member_remove.yml) | `net localgroup/group ... /del` |
| [`win_security_user_account_deleted.yml`](../rules/windows/builtin/security/win_security_user_account_deleted.yml) | Event 4726, any method |
| [`win_security_member_added_privileged_group.yml`](../rules/windows/builtin/security/win_security_member_added_privileged_group.yml) | Events 4728/4732/4756 by group SID |
| [`win_security_member_removed_group.yml`](../rules/windows/builtin/security/win_security_member_removed_group.yml) | Events 4729/4733/4757 by group SID |

## Tuning tips
- Raise severity when the parent is unusual (Office, `wscript`, `mshta`, `w3wp.exe`, a temp folder), it happens outside business hours, or several accounts change within minutes.
- Correlate `net user ... /add` followed within seconds by `net localgroup administrators ... /add` on the same host.
- A short-lived account (created then deleted within hours) is a strong signal.

Spreadsheet version: [`resources/NetExe_Account_Variations.xlsx`](../resources/NetExe_Account_Variations.xlsx)
