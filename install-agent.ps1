<#
  Install, upgrade or remove the CloudCentric edge agent on Windows - the
  PowerShell counterpart of install-agent.sh (design doc sec. 9.2): fetch the
  cloudcentric-agent release for this machine (<version>/windows_<arch>/),
  verify its sha256 AND its Ed25519 release signature before anything on the
  machine changes, install it under C:\ProgramData\CloudCentric (SYSTEM and
  Administrators only), enroll the host once, and run it as the Windows
  service "cloudcentric-agent" - rolling back by itself if a new version does
  not stay up.

  As Administrator (Windows 10 1809+ / Server 2019+, PowerShell 5.1 or 7):

    $env:CC_ENROLL_TOKEN = 'cce1.host_...'
    & ([scriptblock]::Create((irm https://raw.githubusercontent.com/MaiWittawat/edge-connector-releases/main/install-agent.ps1))) -Server crm.example.com:443

    .\install-agent.ps1 -Token T -Server HOST:PORT [-Channel stable | -Version V]
        [-CaCertFile F] [-TlsServerName N] [-TrustedKey id=base64,...] [-BaseUrl URL] [-Root DIR]
    .\install-agent.ps1                      # again = upgrade (same host, same identity)
    .\install-agent.ps1 -Uninstall [-Purge]

  The token is used once, by `cloudcentric-agent enroll`, and never written
  to disk.

  Layout:
    <root>\agent\<version>\bin\cloudcentric-agent.exe   every installed agent version (last 3 kept)
    <root>\agent\current                                the running version's name
    <root>\bin\cloudcentric-agent.cmd                   runs the current version (support CLI)
    <root>\etc\agent.yaml                               server, trust, releases (never overwritten)
    <root>\etc\host.identity.json                       the host's key (kept on upgrade/uninstall)
    <root>\log\agent.log                                the service's log (10 MB x 5)
    service cloudcentric-agent                          `cloudcentric-agent.exe run --root <root>`

  Trust chain: this script is fetched over HTTPS from the release host, and
  the release build bakes the base URL and the trusted signing keys into it.
  The manifest names the artifact's sha256 and size and carries an Ed25519
  signature over "cc-artifact:<name>:<version>:<os>:<arch>:<sha256>"; the
  script checks size + sha256, then the signature itself (Ed25519 below -
  never with the binary being verified). No trusted key = nothing installed
  (unless -InsecureSkipSignature: sha256 only, trust = HTTPS of the base URL).
  The same keys go into agent.yaml (trusted_keys) for every plugin.
#>
[CmdletBinding()]
param(
	[string]$Token = $env:CC_ENROLL_TOKEN,
	[string]$Server = '',
	[string]$Channel = 'stable',
	[string]$Version = '',
	[string]$BaseUrl = $(if ($env:CC_RELEASE_URL) { $env:CC_RELEASE_URL } else { 'https://raw.githubusercontent.com/MaiWittawat/edge-connector-releases/main' }),
	[string]$CaCertFile = '',
	[string]$TlsServerName = '',
	[string[]]$TrustedKey = @(),
	[string]$Root = $(if ($env:CC_ROOT) { $env:CC_ROOT } else { 'C:\ProgramData\CloudCentric' }),
	[switch]$InsecureSkipSignature,
	[switch]$Uninstall,
	[switch]$Purge,
	[int]$HealthWait = $(if ($env:CC_HEALTH_WAIT) { [int]$env:CC_HEALTH_WAIT } else { 15 })
)

Set-StrictMode -Version 2
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue' # Invoke-WebRequest is slow with a progress bar
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

$BakedKeys = 'release-2026=z+2JAsL/vL5CKT1VlAWn0tpuc6hCWKiMi4C1Wxt9Xdc=' # "key_id=base64 ..." - set by the release build
$Name = 'cloudcentric-agent'
$DefaultRoot = 'C:\ProgramData\CloudCentric'

function Say([string]$m) { Write-Host "==> $m" -ForegroundColor Cyan }
function Warn([string]$m) { Write-Warning $m }
function Die([string]$m) { throw "error: $m" }
# Prop is $o.$n, or $null when the JSON has no such field (StrictMode would throw).
function Prop($o, [string]$n) { if ($null -ne $o -and $o.PSObject.Properties[$n]) { return $o.$n } return $null }

# Exec runs a native program and fails on a non-zero exit code. Its output
# goes to the console, never into the caller's return value.
function Exec([string]$exe, [string[]]$argv) {
	& $exe @argv | Out-Host
	if ($LASTEXITCODE -ne 0) { Die "$(Split-Path -Leaf $exe) $($argv -join ' ') failed (exit $LASTEXITCODE)" }
}

# -- Ed25519 verification (RFC 8032, as Go's crypto/ed25519.Verify) ----------
$Ed25519Source = @'
using System;
using System.Numerics;
using System.Security.Cryptography;

public static class CcEd25519 {
	static readonly BigInteger P = BigInteger.Pow(2, 255) - 19;
	static readonly BigInteger L = BigInteger.Pow(2, 252) + BigInteger.Parse("27742317777372353535851937790883648493");
	static readonly BigInteger D = Mod(-121665 * Inv(121666));
	static readonly BigInteger I = BigInteger.ModPow(2, (P - 1) / 4, P);
	static readonly BigInteger[] B = BasePoint();

	static BigInteger Mod(BigInteger a) { BigInteger r = a % P; return r.Sign < 0 ? r + P : r; }
	static BigInteger Inv(BigInteger a) { return BigInteger.ModPow(Mod(a), P - 2, P); }

	static BigInteger LE(byte[] b, int off, int len) {
		byte[] t = new byte[len + 1];
		Array.Copy(b, off, t, 0, len);
		return new BigInteger(t); // trailing 0: always positive
	}

	static BigInteger[] BasePoint() {
		BigInteger y = Mod(4 * Inv(5));
		byte[] enc = new byte[32];
		byte[] yb = y.ToByteArray();
		Array.Copy(yb, enc, Math.Min(32, yb.Length));
		return Decode(enc);
	}

	// Decode a point (x, y, z, t), or null.
	static BigInteger[] Decode(byte[] b) {
		if (b.Length != 32) return null;
		int sign = b[31] >> 7;
		byte[] c = (byte[])b.Clone();
		c[31] &= 0x7f;
		BigInteger y = LE(c, 0, 32);
		if (y >= P) return null;
		BigInteger u = Mod(y * y - 1), v = Mod(D * y * y + 1);
		BigInteger x2 = Mod(u * Inv(v));
		BigInteger x = BigInteger.ModPow(x2, (P + 3) / 8, P);
		if (Mod(x * x - x2) != 0) x = Mod(x * I);
		if (Mod(x * x - x2) != 0) return null;
		if (x.IsZero && sign == 1) return null;
		if ((int)(x % 2) != sign) x = P - x;
		return new BigInteger[] { x, y, 1, Mod(x * y) };
	}

	static BigInteger[] Add(BigInteger[] p, BigInteger[] q) {
		BigInteger a = Mod((p[1] - p[0]) * (q[1] - q[0]));
		BigInteger b = Mod((p[1] + p[0]) * (q[1] + q[0]));
		BigInteger c = Mod(p[3] * 2 * D * q[3]);
		BigInteger d = Mod(p[2] * 2 * q[2]);
		BigInteger e = Mod(b - a), f = Mod(d - c), g = Mod(d + c), h = Mod(b + a);
		return new BigInteger[] { Mod(e * f), Mod(g * h), Mod(f * g), Mod(e * h) };
	}

	static BigInteger[] Mul(BigInteger s, BigInteger[] p) {
		BigInteger[] q = new BigInteger[] { 0, 1, 1, 0 };
		for (int i = 255; i >= 0; i--) {
			q = Add(q, q);
			if (!(s >> i).IsEven) q = Add(q, p);
		}
		return q;
	}

	static byte[] Encode(BigInteger[] p) {
		BigInteger zi = Inv(p[2]);
		BigInteger x = Mod(p[0] * zi), y = Mod(p[1] * zi);
		byte[] o = new byte[32];
		byte[] yb = y.ToByteArray();
		Array.Copy(yb, o, Math.Min(32, yb.Length));
		if (!x.IsEven) o[31] |= 0x80;
		return o;
	}

	// Verify: [S]B - [k]A must encode to R (k = SHA-512(R || A || msg) mod L).
	public static bool Verify(byte[] pub, byte[] sig, byte[] msg) {
		if (pub == null || sig == null || pub.Length != 32 || sig.Length != 64) return false;
		BigInteger[] a = Decode(pub);
		if (a == null) return false;
		BigInteger s = LE(sig, 32, 32);
		if (s >= L) return false;
		byte[] h;
		using (SHA512 sha = SHA512.Create()) {
			byte[] buf = new byte[64 + msg.Length];
			Array.Copy(sig, 0, buf, 0, 32);
			Array.Copy(pub, 0, buf, 32, 32);
			Array.Copy(msg, 0, buf, 64, msg.Length);
			h = sha.ComputeHash(buf);
		}
		BigInteger k = LE(h, 0, 64) % L;
		BigInteger[] negA = new BigInteger[] { Mod(-a[0]), a[1], a[2], Mod(-a[3]) };
		byte[] r = Encode(Add(Mul(s, B), Mul(k, negA)));
		for (int i = 0; i < 32; i++) if (r[i] != sig[i]) return false;
		return true;
	}
}
'@

function Test-Ed25519([string]$pubB64, [string]$sigB64, [string]$message) {
	if (-not ('CcEd25519' -as [type])) {
		if ($PSVersionTable.PSEdition -eq 'Core') { Add-Type -TypeDefinition $Ed25519Source }
		else { Add-Type -TypeDefinition $Ed25519Source -ReferencedAssemblies System.Numerics }
	}
	$pub = [Convert]::FromBase64String($pubB64)
	if ($pub.Length -eq 44) { $pub = $pub[12..43] } # DER SubjectPublicKeyInfo -> the raw 32 bytes
	$sig = [Convert]::FromBase64String($sigB64)
	return [CcEd25519]::Verify($pub, $sig, [Text.Encoding]::UTF8.GetBytes($message))
}

# -- checks ------------------------------------------------------
if ($env:OS -ne 'Windows_NT') { Die 'this is the Windows installer - use install-agent.sh on Linux / macOS' }
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { Die 'run as Administrator' }
$cpu = if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }
switch ($cpu) {
	'AMD64' { $Arch = 'amd64' }
	'ARM64' { $Arch = 'arm64' }
	default { Die "unsupported CPU: $cpu" }
}
if (-not [IO.Path]::IsPathRooted($Root)) { Die '-Root must be an absolute path' }
$Root = $Root.TrimEnd('\')
$Rel = Join-Path $Root 'agent'
$Etc = Join-Path $Root 'etc'
$Cfg = Join-Path $Etc 'agent.yaml'
$Shim = Join-Path $Root "bin\$Name.cmd"
$LogFile = Join-Path $Root 'log\agent.log'
$Exe = "$Name.exe"

function Get-CurrentVersion {
	$f = Join-Path $Rel 'current'
	if (Test-Path -LiteralPath $f -PathType Leaf) { return (Get-Content -LiteralPath $f -Raw).Trim() }
	return ''
}
function AgentExe([string]$v) { return Join-Path $Rel "$v\bin\$Exe" }
function Get-Svc { return Get-Service -Name $Name -ErrorAction SilentlyContinue }

# -- uninstall ---------------------------------------------------
if ($Uninstall) {
	$cur = Get-CurrentVersion
	if ($cur -and (Test-Path -LiteralPath (AgentExe $cur))) {
		if ($Purge) { Exec (AgentExe $cur) @('uninstall', '--root', $Root, '--purge', '--yes') }
		else { Exec (AgentExe $cur) @('uninstall', '--root', $Root) }
	} else {
		Warn "no installed agent found under $Rel - removing what is left"
		if (Get-Svc) { Stop-Service -Name $Name -Force -ErrorAction SilentlyContinue; & sc.exe delete $Name | Out-Null }
	}
	foreach ($d in @($Rel, (Join-Path $Root 'bin'), (Join-Path $Root 'plugins'), (Join-Path $Root 'run'))) {
		if (Test-Path -LiteralPath $d) { Remove-Item -LiteralPath $d -Recurse -Force }
	}
	if ($Purge -and (Test-Path -LiteralPath $Root)) { Remove-Item -LiteralPath $Root -Recurse -Force }
	Say "$Name removed"
	return
}

if ($BaseUrl -like '__*' -or -not $BaseUrl) { Die 'no release URL: pass -BaseUrl or set CC_RELEASE_URL' }
$BaseUrl = $BaseUrl.TrimEnd('/')
$AllKeys = @()
if ($BakedKeys -notlike '__*') { $AllKeys += ($BakedKeys -split '\s+' | Where-Object { $_ }) }
foreach ($k in $TrustedKey) { $AllKeys += ($k -split '[,\s]+' | Where-Object { $_ }) }
foreach ($k in $AllKeys) { if ($k -notmatch '^[^=]+=.+$') { Die "-TrustedKey needs ID=BASE64 (got '$k')" } }
function Test-Segment([string]$s) { return ($s -match '^[A-Za-z0-9][A-Za-z0-9._+-]*$') }

$Tmp = Join-Path ([IO.Path]::GetTempPath()) ("cc-install-" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $Tmp | Out-Null
try {
	function Fetch([string]$url, [string]$out) { Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $out }

	# -- 1. find the release --------------------------------------
	if (-not $Version) {
		if (-not (Test-Segment $Channel)) { Die "bad channel: $Channel" }
		try { Fetch "$BaseUrl/$Name/channels/$Channel.json" "$Tmp\channel.json" }
		catch { Die "cannot read channel ${Channel}: $BaseUrl/$Name/channels/$Channel.json ($($_.Exception.Message))" }
		$Version = [string](Prop (Get-Content -LiteralPath "$Tmp\channel.json" -Raw | ConvertFrom-Json) 'version')
		if (-not (Test-Segment $Version)) { Die "channel $Channel names no usable version" }
		Say "channel $Channel -> $Name $Version"
	}
	if (-not (Test-Segment $Version)) { Die "bad version: $Version" }
	$Murl = "$BaseUrl/$Name/$Version/windows_$Arch/manifest.json"
	try { Fetch $Murl "$Tmp\manifest.json" } catch { Die "no $Name $Version for windows/$Arch ($Murl)" }
	$M = Get-Content -LiteralPath "$Tmp\manifest.json" -Raw | ConvertFrom-Json
	$said = "$(Prop $M 'name') $(Prop $M 'version') $(Prop $M 'os') $(Prop $M 'arch')"
	if ($said -ne "$Name $Version windows $Arch") { Die "manifest at $Murl says '$said' - not installing" }
	$A = Prop $M 'artifact'
	$AUrl, $ASize, $ASig, $AKid = [string](Prop $A 'url'), [string](Prop $A 'size'), [string](Prop $A 'signature'), [string](Prop $A 'keyId')
	$ASha = ([string](Prop $A 'sha256')).ToLowerInvariant()
	if ($ASha -notmatch '^[0-9a-f]{64}$') { Die 'manifest sha256 is not 64 hex characters' }
	if ($AUrl -notmatch '^https?://') { Die "artifact url must be http(s): $AUrl" }

	# -- 2. download + verify (nothing on the system changes before this passes)
	Say "downloading $Name $Version (windows/$Arch)"
	$Archive = "$Tmp\agent.tar.gz"
	try { Fetch $AUrl $Archive } catch { Die "download failed: $AUrl" }
	$size = (Get-Item -LiteralPath $Archive).Length
	if ($ASize -and [int64]$ASize -ne $size) { Die "size mismatch (want $ASize, got $size) - not installing" }
	$got = (Get-FileHash -LiteralPath $Archive -Algorithm SHA256).Hash.ToLowerInvariant()
	if ($got -ne $ASha) { Die "checksum mismatch (want $ASha, got $got) - not installing" }

	if ($InsecureSkipSignature) {
		Warn "-InsecureSkipSignature: only the sha256 was checked (trust = HTTPS of $BaseUrl)"
	} else {
		$kid = $AKid
		if (-not $ASig -or -not $kid) { Die 'the release is not signed - not installing' }
		$pub = $null
		foreach ($k in $AllKeys) { if (-not $pub -and ($k -split '=', 2)[0] -eq $kid) { $pub = ($k -split '=', 2)[1] } }
		if (-not $pub) { Die "the release is signed with key '$kid', which this installer does not trust (-TrustedKey $kid=...) - not installing" }
		$msg = "cc-artifact:${Name}:${Version}:windows:${Arch}:$ASha"
		if (-not (Test-Ed25519 $pub $ASig $msg)) { Die "BAD SIGNATURE on $Name $Version (key $kid) - not installing" }
		Say "signature ok (key $kid)"
	}

	$X = Join-Path $Tmp 'x'
	New-Item -ItemType Directory -Path $X | Out-Null
	Exec "$env:SystemRoot\System32\tar.exe" @('-xzf', $Archive, '-C', $X)
	$NewBin = Join-Path $X "bin\$Exe"
	if (-not (Test-Path -LiteralPath $NewBin -PathType Leaf)) { Die "archive has no bin/$Exe" }
	$NewVer = (& $NewBin version)
	if ($LASTEXITCODE -ne 0) { Die "the downloaded agent does not run on this machine (windows/$Arch)" }
	if ($NewVer -ne $Version) { Warn "the binary says version '$NewVer', the release says $Version" }
	Say "verified $Name $Version"

	# -- 3. the root (SYSTEM + Administrators only) and the version -
	foreach ($d in @($Root, $Rel, (Join-Path $Root 'bin'), $Etc)) {
		if (-not (Test-Path -LiteralPath $d)) { New-Item -ItemType Directory -Path $d | Out-Null }
	}
	# The root alone gets an explicit ACL; everything under it inherits it
	# (/reset: just the inherited ACEs). SIDs, not names: names are localized
	# (S-1-5-18 SYSTEM, S-1-5-32-544 Administrators).
	& icacls.exe $Root /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' /Q | Out-Null
	if ($LASTEXITCODE -ne 0) { Die "could not restrict the permissions of $Root (icacls exit $LASTEXITCODE)" }
	& icacls.exe "$Root\*" /reset /T /C /Q | Out-Null
	if ($LASTEXITCODE -ne 0) { Warn "some files under $Root keep their own permissions (icacls /reset exit $LASTEXITCODE)" }
	$Prev = Get-CurrentVersion
	if (-not (Test-Path -LiteralPath (Join-Path $Rel $Version))) {
		$stage = Join-Path $Rel ".$Version.tmp"
		if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Recurse -Force }
		Copy-Item -LiteralPath $X -Destination $stage -Recurse
		Rename-Item -LiteralPath $stage -NewName $Version
	}
	$VerExe = AgentExe $Version

	# -- 4. agent.yaml (written once; edit it afterwards) ---------
	function Q([string]$s) { return "'" + $s.Replace("'", "''") + "'" } # YAML single-quoted: no escapes, Windows paths as they are
	if (Test-Path -LiteralPath $Cfg) {
		if ($Server -or $CaCertFile -or $TlsServerName -or $TrustedKey) { Warn "kept the existing $Cfg - edit it to change server / ca_cert / trusted_keys" }
	} else {
		if (-not $Server) { Die '-Server HOST:PORT is required for the first install' }
		$lines = @("# $Cfg - written by install-agent.ps1; see agent/packaging/agent.yaml for every setting.", "server: $(Q $Server)")
		if ($Root -ne $DefaultRoot) { $lines += 'paths:'; $lines += "  root: $(Q $Root)" }
		if ($CaCertFile) {
			if (-not (Test-Path -LiteralPath $CaCertFile -PathType Leaf)) { Die "no such file: $CaCertFile" }
			Copy-Item -LiteralPath $CaCertFile -Destination (Join-Path $Etc 'ca.pem') -Force
			$lines += "ca_cert: $(Q (Join-Path $Etc 'ca.pem'))"
		}
		if ($TlsServerName) { $lines += "tls_server_name: $(Q $TlsServerName)" }
		$lines += "releases: $(Q $BaseUrl)"
		$seen = @{}
		$keyLines = @()
		foreach ($k in $AllKeys) {
			$id, $b64 = $k -split '=', 2
			if ($seen.ContainsKey($id)) { continue }
			$seen[$id] = $true
			$keyLines += "  ${id}: $(Q $b64)"
		}
		if ($keyLines.Count -eq 0) { $lines += 'trusted_keys: {}' } else { $lines += 'trusted_keys:'; $lines += $keyLines }
		[IO.File]::WriteAllLines("$Cfg.tmp", [string[]]$lines, (New-Object Text.UTF8Encoding($false)))
		Move-Item -LiteralPath "$Cfg.tmp" -Destination $Cfg -Force
		Say "wrote $Cfg"
	}

	# -- 5. enroll once (the token is never written anywhere) -----
	if (Test-Path -LiteralPath (Join-Path $Etc 'host.identity.json')) {
		if ($Token) { Warn "already enrolled ($Etc\host.identity.json) - ignoring the token" }
	} else {
		if (-not $Token) { Die 'not enrolled yet: give -Token (or CC_ENROLL_TOKEN)' }
		Say 'enrolling this host'
		$env:CC_ENROLL_TOKEN = $Token
		try { & $VerExe enroll --root $Root | Out-Null } finally { Remove-Item Env:\CC_ENROLL_TOKEN -ErrorAction SilentlyContinue }
		if ($LASTEXITCODE -ne 0) { Die 'enrollment failed - nothing was switched; check the token, -Server and the CA' }
	}
	$Token = ''

	# -- 6. switch + service --------------------------------------
	function Switch-To([string]$v) {
		[IO.File]::WriteAllText((Join-Path $Rel 'current.tmp'), "$v`n")
		Move-Item -LiteralPath (Join-Path $Rel 'current.tmp') -Destination (Join-Path $Rel 'current') -Force
		[IO.File]::WriteAllText($Shim, "@`"%~dp0..\agent\$v\bin\$Exe`" %*`r`n")
		Exec (AgentExe $v) @('service', 'install', '--root', $Root) # creates the service, or points it at this version
	}
	function Stop-Agent {
		if (Get-Svc) {
			$cur = Get-CurrentVersion
			$exe = if ($cur -and (Test-Path -LiteralPath (AgentExe $cur))) { AgentExe $cur } else { $VerExe }
			& $exe service stop --root $Root | Out-Null
			if ($LASTEXITCODE -ne 0) { Stop-Service -Name $Name -Force -ErrorAction SilentlyContinue } # that binary is broken
		}
	}
	function Start-Agent([string]$v) { & (AgentExe $v) service start --root $Root | Out-Null; return ($LASTEXITCODE -eq 0) }
	# Get-HealthyStatus: up for HealthWait s without a restart, answering on
	# its control socket as version v -> its `status --json`; else $null.
	function Get-HealthyStatus([string]$v) {
		Start-Sleep -Seconds 1
		$pid0 = (Get-CimInstance Win32_Service -Filter "Name='$Name'").ProcessId
		for ($i = 0; $i -lt $HealthWait; $i++) {
			$s = Get-CimInstance Win32_Service -Filter "Name='$Name'"
			if ($s.State -ne 'Running' -or $s.ProcessId -ne $pid0) { return $null } # stopped, or restarted by the recovery actions
			Start-Sleep -Seconds 1
		}
		$json = (& (AgentExe $v) status --root $Root --json | Out-String)
		if ($LASTEXITCODE -ne 0 -or $json -match '"connection":\s*"agent not running"') { return $null }
		if ([string](Prop ($json | ConvertFrom-Json) 'agent_version') -ne $v) { return $null } # the service runs another binary
		return $json
	}
	function Show-Log { if (Test-Path -LiteralPath $LogFile) { Get-Content -LiteralPath $LogFile -Tail 20 } }
	function Remove-OldVersions {
		Get-ChildItem -LiteralPath $Rel -Directory | Where-Object { $_.Name -notlike '.*' } |
			Sort-Object LastWriteTime -Descending | Select-Object -Skip 3 |
			Where-Object { $_.Name -ne $Version -and $_.Name -ne $Prev } |
			ForEach-Object { Remove-Item -LiteralPath $_.FullName -Recurse -Force -ErrorAction SilentlyContinue }
	}

	# Try-Start: switch to v, start it, wait for health -> its status, or $null
	# (a version too broken to even register the service counts as not up)
	function Try-Start([string]$v) {
		try {
			Switch-To $v
			if (Start-Agent $v) { return Get-HealthyStatus $v }
		} catch { Warn "$Name ${v}: $($_.Exception.Message)" }
		return $null
	}

	Stop-Agent
	Say "starting $Name $Version"
	$json = Try-Start $Version
	if ($json) {
		Remove-OldVersions
		$st = $json | ConvertFrom-Json
		$conn = [string](Prop $st 'connection')
		if ($conn -ne 'connected') { Warn "the agent runs but is not connected to the CRM yet ($conn) - see: $Shim doctor" }
		Say "$Name $Version is running - host $(Prop $st 'host_id'), $conn (log: $LogFile - $Shim status)"
		return
	}

	Show-Log
	if ($Prev -and $Prev -ne $Version -and (Test-Path -LiteralPath (AgentExe $Prev))) {
		Warn "$Name $Version did not stay up - rolling back to $Prev"
		Stop-Agent
		if (Try-Start $Prev) { Die "upgrade to $Version failed; $Prev is running again" }
		Die "upgrade to $Version failed and $Prev does not stay up either - see $LogFile"
	}
	Stop-Agent
	Die "$Name $Version does not stay up - see $LogFile and: $Shim doctor"
} finally {
	Remove-Item -LiteralPath $Tmp -Recurse -Force -ErrorAction SilentlyContinue
}
