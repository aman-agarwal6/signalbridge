"""Read-only ACL security contracts; never execute the Windows helper or fixture.

These checks catch consequential source regressions. They do not establish that
Windows accepts the DACL write; that requires an actual Windows fixture check.
"""

import re
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "integrations/enterprise/reference-private-acl.ps1"
FIXTURE = ROOT / "scripts/verify_reference_acl.ps1"


class ReferencePrivateAclStaticTests(unittest.TestCase):
    def setUp(self):
        for target in (
            "subprocess.Popen",
            "subprocess.run",
            "os.system",
            "socket.socket",
            "socket.create_connection",
        ):
            guard = patch(target, side_effect=AssertionError("Unexpected native or network call."))
            guard.start()
            self.addCleanup(guard.stop)
        self.source = HELPER.read_text(encoding="utf-8")
        self.fixture = FIXTURE.read_text(encoding="utf-8")

    def test_persistence_cannot_request_owner_group_or_audit_changes(self):
        self.assertNotRegex(self.source, r"(?i)\bSet-Acl\b|\.Set(?:Owner|Group|Audit\w*)\s*\(")
        sections = re.findall(r"AccessControlSections\]::(\w+)", self.source)
        self.assertEqual(sections, ["Access"])
        self.assertEqual(self.source.count("::SetAccessControl("), 1)
        self.assertIn("[IO.Directory]::SetAccessControl($runPath, $accessOnlyAcl)", self.source)
        copy = "$accessOnlyAcl.SetSecurityDescriptorSddlForm($descriptor, $accessSection)"
        self.assertIn(
            "$descriptor = $newAcl.GetSecurityDescriptorSddlForm($accessSection)", self.source
        )
        self.assertIn(
            "$accessOnlyAcl = [Security.AccessControl.DirectorySecurity]::new()", self.source
        )
        self.assertLess(self.source.index(copy), self.source.index("::SetAccessControl("))

    def test_existing_owner_must_match_before_any_dacl_write(self):
        preflight = "$existingAcl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $identity.Value"
        self.assertIn("$existingAcl = Get-Acl -LiteralPath $runPath", self.source)
        self.assertIn(preflight, self.source)
        self.assertLess(self.source.index(preflight), self.source.index("$newAcl ="))
        self.assertLess(self.source.index(preflight), self.source.index("::SetAccessControl("))
        # A second ownership check still reads actual post-write state.
        self.assertIn(
            "$acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $identity.Value",
            self.source,
        )

    def test_nonempty_runs_cannot_be_reinitialized(self):
        secure = self.source.index("if ($Mode -eq 'SecureEmpty')")
        empty = self.source.index("@(Get-ChildItem -LiteralPath $runPath -Force).Count -ne 0")
        write = self.source.index("::SetAccessControl(")
        self.assertLess(secure, empty)
        self.assertLess(empty, write)
        self.assertIn("throw 'Only a fresh empty private run can be secured.'", self.source)

    def test_only_current_user_and_system_receive_exact_full_control(self):
        self.assertIn("WindowsIdentity]::GetCurrent().User", self.source)
        self.assertIn("SecurityIdentifier]::new('S-1-5-18')", self.source)
        self.assertIn("$allowed = @($identity.Value, $systemIdentity.Value)", self.source)
        self.assertIn("foreach ($principal in @($identity, $systemIdentity))", self.source)
        self.assertIn("$newAcl.SetAccessRuleProtection($true, $false)", self.source)
        for control in (
            "$full = [Security.AccessControl.FileSystemRights]::FullControl",
            "$allow = [Security.AccessControl.AccessControlType]::Allow",
            "$propagate = [Security.AccessControl.PropagationFlags]::None",
            "$rules.Count -ne 2",
            "$sid -notin $allowed -or $sid -in $seen",
            "$rule.AccessControlType -ne $allow",
            "$rule.FileSystemRights -ne $full",
            "$rule.PropagationFlags -ne $propagate",
            "$rule.InheritanceFlags -ne $inherit",
            "[Security.AccessControl.InheritanceFlags]::None",
            "$path -eq $runPath -and -not $acl.AreAccessRulesProtected",
        ):
            with self.subTest(control=control):
                self.assertIn(control, self.source)

    def test_redirected_parents_and_items_are_rejected_before_recursion(self):
        for control in (
            "$Run -cnotmatch '^[a-f0-9]{32}$'",
            "[IO.Path]::IsPathRooted($Workspace)",
            "$runPath.StartsWith($workspacePath + '\\', [StringComparison]::OrdinalIgnoreCase)",
            "$ancestor -isnot [IO.DirectoryInfo]",
            "$ancestor.Attributes -band [IO.FileAttributes]::ReparsePoint",
            "$null -eq $ancestor",
            "$item.Attributes -band [IO.FileAttributes]::ReparsePoint",
            "++$checked -gt 2500",
        ):
            with self.subTest(control=control):
                self.assertIn(control, self.source)
        self.assertNotIn("-Recurse", self.source)
        self.assertLess(
            self.source.index("$rule.FileSystemRights"),
            self.source.index("$pending.Enqueue($child.FullName)"),
        )

    def test_failure_protocol_is_bounded_fixed_branch_metadata_only(self):
        caught = self.source.split("} catch {", 1)[1]
        fields = re.findall(r"^\s*(\w+)\s*=\s*(.+)$", caught, flags=re.MULTILINE)
        self.assertEqual(
            fields,
            [
                ("kind", "'signalbridge-private-acl-failure'"),
                ("mode", "$diagnosticMode"),
                ("phase", "$phase"),
                ("checked_count", "[Math]::Min($checked, 2501)"),
            ],
        )
        self.assertEqual(caught.count("$_.Exception"), 1)
        numeric_only = caught.replace("$_.Exception", "approved-exception-source")
        self.assertNotRegex(
            numeric_only,
            r"\$_|\$Error\b|\.Exception\b|\.Message\b|\.GetType\b|\.ToString\b|GetLastWin32Error|"
            r"\$Workspace\b|\$Run\b|\$identity\b|\$sid\b",
        )
        self.assertIn("[Console]::Error.WriteLine(($failure | ConvertTo-Json -Compress))", caught)
        self.assertIn("exit 1", caught)
        self.assertIn("$checked = 0", self.source.split("try {", 1)[0])
        self.assertIn(
            "$diagnosticMode = if ($Mode -ieq 'SecureEmpty') { 'SecureEmpty' } else { 'Verify' }",
            self.source,
        )
        phases = [int(value) for value in re.findall(r"\$phase = (\d+)\b", self.source)]
        self.assertEqual(phases, list(range(1, 18)))

    def test_numeric_error_is_phase8_only_and_requires_a_completed_bounded_chain(self):
        caught = self.source.split("} catch {", 1)[1]
        self.assertEqual(caught.count("$failure['api_hresult'] = $apiHResult"), 1)
        self.assertLess(caught.index("if ($phase -eq 8)"), caught.index("$apiHResult = $null"))
        self.assertIn("$innerLinks = 0", caught)
        self.assertIn("$innerLinks -lt 4", caught)
        self.assertIn("++$innerLinks", caught)
        self.assertIn("$null -eq $diagnosticException.InnerException", caught)
        self.assertIn("$diagnosticException.HResult -is [int]", caught)
        self.assertIn("$apiHResult = $diagnosticException.HResult", caught)
        self.assertIn('"phase":8,', self.fixture)
        self.assertIn("$value.phase -ne 8", self.fixture)
        self.assertIn("$value.api_hresult -isnot [int]", self.fixture)
        self.assertIn("(?:null|0|-?[1-9][0-9]{0,9})", self.fixture)

    def test_success_protocol_remains_exactly_the_two_original_true_keys(self):
        success = re.findall(r"@\{\s*(.*?)\s*\}\s*\| ConvertTo-Json -Compress", self.source)
        self.assertEqual(
            success,
            ["private_acl_verified = $true; inherited_public_access_removed = $true"],
        )
        # No extra command can disclose the descriptor or grant list.
        commands = re.findall(r"\b(?:Write-\w+|Out-\w+|Set-\w+)\b", self.source)
        self.assertEqual(commands, ["Set-StrictMode"])

    def test_unrun_windows_fixture_checks_owner_and_closed_output_protocol(self):
        self.assertIn("$originalOwner = (Get-Acl -LiteralPath $runPath).GetOwner", self.fixture)
        self.assertEqual(self.fixture.count(".Value -ne $originalOwner"), 2)
        self.assertIn("$names.Count -ne 2", self.fixture)
        self.assertIn("$names[0] -cne 'inherited_public_access_removed'", self.fixture)
        self.assertIn("$names[1] -cne 'private_acl_verified'", self.fixture)
        self.assertIn("elseif ($process.ExitCode -ne 1 -or $output.Length -ne 0", self.fixture)
        self.assertEqual(self.fixture.count("$checks.Add("), 8)

    def test_fixture_cannot_delete_a_collision_or_follow_redirected_parents(self):
        create = self.fixture.index("New-Item -ItemType Directory -Path $testWorkspace")
        owned = self.fixture.index("$scopeCreated = $true")
        cleanup = self.fixture.index("if ($scopeCreated) {")
        self.assertLess(self.fixture.index("if (Test-Path -LiteralPath $testWorkspace)"), create)
        self.assertLess(create, owned)
        self.assertLess(owned, cleanup)
        self.assertIn("$scopeCreated = $false", self.fixture)
        self.assertEqual(self.fixture.count("Assert-WorkspaceAncestors $testParent"), 2)
        self.assertIn("$ancestor -isnot [IO.DirectoryInfo]", self.fixture)
        self.assertIn("$ancestor.Attributes -band [IO.FileAttributes]::ReparsePoint", self.fixture)
        self.assertIn("++$cleanupCount -gt 2500", self.fixture)
        self.assertIn("$cleanupClock.ElapsedMilliseconds -gt 5000", self.fixture)
        self.assertIn("if (-not $childExitedVerified)", self.fixture)

    def test_fixture_children_are_finite_and_keep_only_validated_diagnostics(self):
        self.assertIn("$start.UseShellExecute = $false", self.fixture)
        self.assertIn("$start.CreateNoWindow = $true", self.fixture)
        self.assertIn("$process.WaitForExit(30000)", self.fixture)
        self.assertIn("$process.WaitForExit(5000)", self.fixture)
        self.assertEqual(self.fixture.count("$process.Start()"), 1)
        self.assertEqual(self.fixture.count("$process.Kill()"), 1)
        self.assertEqual(self.fixture.count("[byte[]]::new(1025)"), 2)
        self.assertNotIn("ReadToEnd", self.fixture)
        self.assertIn("if ($used -gt 1024)", self.fixture)
        self.assertIn("$remaining = 1000 - [int]$clock.ElapsedMilliseconds", self.fixture)
        self.assertIn("$start.EnvironmentVariables.Clear()", self.fixture)
        for name in (
            "SYSTEMROOT",
            "WINDIR",
            "PATH",
            "TEMP",
            "TMP",
            "USERPROFILE",
            "LOCALAPPDATA",
            "APPDATA",
            "PROGRAMDATA",
            "SYSTEMDRIVE",
            "PYTHONDONTWRITEBYTECODE",
            "PYTHONUTF8",
            "COMPOSE_DISABLE_ENV_FILE",
        ):
            with self.subTest(name=name):
                self.assertIn("'" + name + "'", self.fixture)
        self.assertIn(
            "$script:lastHelperDiagnostic = Read-FixedDiagnostic $errorOutput $Mode", self.fixture
        )
        for boundary in (
            "($names -join ',') -cne $fields",
            "$value.kind -cne 'signalbridge-private-acl-failure'",
            "$value.mode -cne $ExpectedMode",
            "$value.phase -isnot [int]",
            "$value.phase -lt 1 -or $value.phase -gt 17",
            "$value.checked_count -isnot [int]",
            "$value.checked_count -lt 0 -or $value.checked_count -gt 2501",
        ):
            with self.subTest(boundary=boundary):
                self.assertIn(boundary, self.fixture)
        self.assertIn("helper = $lastHelperDiagnostic", self.fixture)
        self.assertIn(
            "if ($Raw -cnotmatch $wire -and $Raw -cnotmatch $numericWire) { return $null }",
            self.fixture,
        )
        self.assertIn("if ($output -cnotmatch $successWire)", self.fixture)
        receipt = self.fixture.split("$receipt = [ordered]@{", 1)[1]
        self.assertNotRegex(receipt, r"\$_|\$Error\b|\$errorOutput\b|\$originalOwner\b")
        self.assertIn("[IO.FileMode]::CreateNew", receipt)

    def test_owned_files_are_utf8_without_bom_or_crlf(self):
        for path in (HELPER, FIXTURE, Path(__file__)):
            with self.subTest(path=path.name):
                raw = path.read_bytes()
                raw.decode("utf-8")
                self.assertFalse(raw.startswith(b"\xef\xbb\xbf"))
                self.assertNotIn(b"\r", raw)


if __name__ == "__main__":
    unittest.main()
