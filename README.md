# .NET 10 and NuGet Audit: Identifying Root Packages for Vulnerable Transitive Dependencies

Ref: https://www.appsoftware.com/blog/net-10-and-nuget-audit-identifying-root-packages-for-vulnerable-transitive-dependencies

As of .NET 10, defaults for `NuGetAuditMode` in NuGet Audit have changed, and this may mean additional warnings regarding NuGet package vulnerabilities (`NU1901`, `NU1902`, `NU1903`, `NU1904`, `NU1905`) in your .NET applications. After upgrading to .NET 10 from .NET 8, builds started reporting vulnerabilities that had not been reported before. GitHub vulnerability scanning hadn't spotted them, and this seems to be because the vulnerable packages were not directly referenced in the app, being transitive (indirect) references via other (directly referenced) packages.

Microsoft documentation says:

https://learn.microsoft.com/en-us/nuget/concepts/auditing-packages#configuring-nuget-audit

> NuGetAuditMode defaults to all when a project targets net10.0 or higher. Otherwise NuGetAuditMode defaults to direct. When a project multi-targets, if any one target framework selects all, then audit will use this value for all target frameworks.

**To Summarise:**

**Previous Default:** In older versions of the .NET SDK (pre-10), the NuGet Audit feature was sometimes set to only check direct dependencies by default (NuGetAuditMode set to direct).

**New .NET 10 Default:** When a project targets net10.0 or higher, the default for the audit mode changes to all.

This means that when you run dotnet restore or build your project, the system now automatically scans both direct and transitive dependencies for vulnerabilities.

`NuGetAuditMode`: 

<table aria-label="Configuring NuGet Audit" class="table table-sm margin-top-none">
<thead>
<tr>
<th>MSBuild Property</th>
<th>Default</th>
<th>Possible values</th>
<th>Notes</th>
</tr>
</thead>
<tbody>
<tr>
<td>NuGetAuditMode</td>
<td>See 1 below</td>
<td><code>direct</code> and <code>all</code></td>
<td>If you'd like to audit top-level dependencies only, you can set the value to <code>direct</code>. NuGetAuditMode is not applicable for packages.config projects.</td>
</tr>
<tr>
<td>NuGetAuditLevel</td>
<td>low</td>
<td><code>low</code>, <code>moderate</code>, <code>high</code>, and <code>critical</code></td>
<td>The minimum severity level to report. If you'd like to see <code>moderate</code>, <code>high</code>, and <code>critical</code> advisories (exclude <code>low</code>), set the value to <code>moderate</code></td>
</tr>
<tr>
<td>NuGetAudit</td>
<td>true</td>
<td><code>true</code> and <code>false</code></td>
<td>If you wish to not receive security audit reports, you can opt-out of the experience entirely by setting the value to <code>false</code></td>
</tr>
</tbody>
</table>


## The Challenge: Identifying Root Packages for Transitive Dependencies

Manually overriding transitive package versions in a .csproj file can be brittle and high-maintenance in large projects. The risk of introducing a breaking change to the primary package is a possibility.

The aim is to identify the root packages and upgrade those.

This can be done using 2 `dotnet` utilities:

```
> dotnet list [solution] package --vulnerable
> dotnet nuget why [solution] [packageName]
```

Running these commands manually can be arduous, and so I have created a file based app (file based apps are new in .NET 10 - read more here https://www.appsoftware.com/blog/net-10-file-based-apps-demonstration-c-scripting) to automatically list vulnerable packages, and then call `dotnet nuget why` and parse the output to link the vulnerability to the root package.


## Prerequisites

1. **.NET 10 SDK** installed (verify with `dotnet --version`)

## How to Run

### Using `dotnet run`

Run the file based app using `dotnet run`

```powershell
dotnet run VulnerabilityScanner.cs
```

## How it Works

The script:

1. **Scans for Solutions**: Identifies solution files (`.sln`) in the current directory.
2. **Identifies Vulnerabilities**: Finds all packages with known security issues using `dotnet list package --vulnerable`
3. **Traces Root Causes**: Determines which top-level packages are bringing in vulnerable transitive dependencies
4. **Generates Report**: Creates `vulnerabilities_<datestamp>.md` report.

## Script (C# File Based App):

Save as `VulnerabilityScanner.cs` in the same directory as your `.sln` file(s) and run with `dotnet run --file VulnerabilityScanner.cs`

```csharp
// > dotnet run --file VulnerabilityScanner.cs          

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

Console.WriteLine("Starting vulnerability scan...");

// Automatically discover all solution files in the current directory
var solutions = Directory.GetFiles(Directory.GetCurrentDirectory(), "*.sln")
    .Select(Path.GetFileName)
    .Where(f => f != null)
    .Cast<string>()
    .ToArray();

if (solutions.Length == 0)
{
    Console.WriteLine("Error: No solution files (.sln) found in the current directory.");
    Environment.Exit(1);
}

Console.WriteLine($"Found {solutions.Length} solution file(s): {string.Join(", ", solutions)}");

var allVulnerabilities = new List<VulnerabilityInfo>();

foreach (var solution in solutions)
{
    if (!File.Exists(solution))
    {
        Console.WriteLine($"Warning: Solution file not found: {solution}");
        continue;
    }

    Console.WriteLine($"\nScanning {solution}...");

    // Run dotnet list package --vulnerable
    var vulnerableOutput = RunCommand("dotnet", $"list \"{solution}\" package --vulnerable");

    var vulnerabilities = ParseVulnerabilities(vulnerableOutput, solution);

    // Get distinct package names to avoid redundant lookups
    var distinctPackages = vulnerabilities
        .Select(v => v.PackageName)
        .Distinct()
        .ToList();

    // Build a cache of root packages for each unique vulnerable package
    var rootPackageCache = new Dictionary<string, List<string>>();

    foreach (var packageName in distinctPackages)
    {
        Console.WriteLine($"  Finding root cause for {packageName}...");
        rootPackageCache[packageName] = FindRootPackages(packageName, solution);
    }

    // Assign root packages from cache to each vulnerability
    foreach (var vuln in vulnerabilities)
    {
        vuln.RootPackages = rootPackageCache[vuln.PackageName];
    }

    allVulnerabilities.AddRange(vulnerabilities);
}

// Generate markdown report
GenerateMarkdownReport(allVulnerabilities);

Console.WriteLine("\nVulnerability scan complete! Report saved to vulnerabilities_<datestamp>.md");

// Helper methods
string RunCommand(string command, string arguments)
{
    var process = new Process
    {
        StartInfo = new ProcessStartInfo
        {
            FileName = command,
            Arguments = arguments,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
            WorkingDirectory = Directory.GetCurrentDirectory()
        }
    };

    var output = new StringBuilder();
    process.OutputDataReceived += (sender, e) => { if (e.Data != null) output.AppendLine(e.Data); };
    process.ErrorDataReceived += (sender, e) => { if (e.Data != null) output.AppendLine(e.Data); };

    process.Start();
    process.BeginOutputReadLine();
    process.BeginErrorReadLine();
    process.WaitForExit();

    return output.ToString();
}

List<VulnerabilityInfo> ParseVulnerabilities(string output, string solution)
{
    var vulnerabilities = new List<VulnerabilityInfo>();
    var lines = output.Split(new[] { '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries);

    foreach (var line in lines)
    {
        // Match MSBuild warning format: path\project.csproj : warning NUXXX: Package 'Name' Version has a known severity vulnerability, URL
        var warningMatch = Regex.Match(line,
            @"([^:]+\.csproj)\s*:\s*warning\s+(NU\d+):\s*Package\s+'([^']+)'\s+([^\s]+)\s+has\s+a\s+known\s+(\w+)\s+severity\s+vulnerability,\s+(https://[^\s\[\]]+)",
            RegexOptions.IgnoreCase);

        if (warningMatch.Success)
        {
            var projectPath = warningMatch.Groups[1].Value.Trim();
            var packageName = warningMatch.Groups[3].Value;
            var version = warningMatch.Groups[4].Value;
            var severity = warningMatch.Groups[5].Value;
            var advisoryUrl = warningMatch.Groups[6].Value;

            vulnerabilities.Add(new VulnerabilityInfo
            {
                Solution = solution,
                Project = projectPath,
                PackageName = packageName,
                Version = version,
                Severity = severity,
                AdvisoryUrl = advisoryUrl,
                RootPackages = new List<string>()
            });
        }
    }

    return vulnerabilities;
}

List<string> FindRootPackages(string packageName, string solution)
{
    var rootPackages = new List<string>();

    // Get list of projects in the solution to filter them out from dependencies
    var projectsOutput = RunCommand("dotnet", $"sln \"{solution}\" list");
    var solutionProjects = projectsOutput.Split(new[] { '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries)
        .Where(line => line.EndsWith(".csproj"))
        .Select(line => Path.GetFileNameWithoutExtension(line))
        .ToHashSet(StringComparer.OrdinalIgnoreCase);

    // Use dotnet nuget why to find the dependency chain
    var whyOutput = RunCommand("dotnet", $"nuget why \"{solution}\" {packageName}");

    var lines = whyOutput.Split(new[] { '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries);

    string? currentProject = null;
    string? rootPackage = null;
    bool inDependencyGraph = false;

    foreach (var line in lines)
    {
        // Match project line: "Project 'ProjectName' has the following dependency graph(s) for 'PackageName'"
        var projectMatch = Regex.Match(line, @"Project\s+'([^']+)'\s+has\s+the\s+following\s+dependency");
        if (projectMatch.Success)
        {
            currentProject = projectMatch.Groups[1].Value;
            rootPackage = null;
            inDependencyGraph = true;
            continue;
        }

        // Skip "does not have a dependency" lines
        if (line.Contains("does not have a dependency"))
        {
            inDependencyGraph = false;
            continue;
        }

        // Skip framework lines like "[net10.0]"
        if (line.Trim().StartsWith("[") && line.Trim().EndsWith("]"))
        {
            continue;
        }

        // Look for the first package in the dependency tree (the root cause)
        // It will be the first line with a package name after the framework line
        if (inDependencyGraph && currentProject != null && rootPackage == null)
        {
            // Match lines with package names and versions: "   └─ PackageName (vX.X.X)"
            var packageMatch = Regex.Match(line, @"[└├─│\s]+([A-Za-z0-9_.]+)\s+\(v([\d.]+)\)");
            if (packageMatch.Success)
            {
                var pkg = packageMatch.Groups[1].Value;
                // This is the root package that brings in the vulnerable dependency
                // Filter out project references from the solution and the target package itself
                if (!pkg.Equals(packageName, StringComparison.OrdinalIgnoreCase) &&
                    !solutionProjects.Contains(pkg))
                {
                    rootPackage = pkg;
                    // Just add the root package name, not the project
                    if (!rootPackages.Contains(rootPackage))
                    {
                        rootPackages.Add(rootPackage);
                    }
                    inDependencyGraph = false; // Stop looking for this project
                }
            }
        }
    }

    return rootPackages.Any() ? rootPackages : new List<string> { "No dependency found" };
}

void GenerateMarkdownReport(List<VulnerabilityInfo> vulnerabilities)
{
    var markdown = new StringBuilder();

    markdown.AppendLine("# NuGet Package Vulnerability Report");
    markdown.AppendLine();
    markdown.AppendLine($"**Generated:** {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
    markdown.AppendLine();
    markdown.AppendLine($"**Total Vulnerabilities Found:** {vulnerabilities.Count}");
    markdown.AppendLine();

    // Group by solution
    var bySolution = vulnerabilities.GroupBy(v => v.Solution);

    foreach (var solutionGroup in bySolution)
    {
        markdown.AppendLine($"## Solution: {solutionGroup.Key}");
        markdown.AppendLine();

        // Group by severity
        var bySeverity = solutionGroup.GroupBy(v => v.Severity)
            .OrderByDescending(g => GetSeverityOrder(g.Key));

        foreach (var severityGroup in bySeverity)
        {
            markdown.AppendLine($"### {severityGroup.Key} Severity ({severityGroup.Count()})");
            markdown.AppendLine();
            markdown.AppendLine("| Package | Version | Project | Root Package(s) | Advisory |");
            markdown.AppendLine("|---------|---------|---------|-----------------|----------|");

            foreach (var vuln in severityGroup.OrderBy(v => v.PackageName))
            {
                var rootPackagesStr = string.Join("<br/>", vuln.RootPackages.Take(3));
                if (vuln.RootPackages.Count > 3)
                {
                    rootPackagesStr += $"<br/>...and {vuln.RootPackages.Count - 3} more";
                }

                var projectName = Path.GetFileName(vuln.Project);
                var advisoryLink = $"[Link]({vuln.AdvisoryUrl})";

                markdown.AppendLine($"| {vuln.PackageName} | {vuln.Version} | {projectName} | {rootPackagesStr} | {advisoryLink} |");
            }

            markdown.AppendLine();
        }
    }

    // Summary section
    markdown.AppendLine("## Summary by Package");
    markdown.AppendLine();

    var byPackage = vulnerabilities.GroupBy(v => v.PackageName)
        .OrderByDescending(g => g.Count());

    markdown.AppendLine("| Package | Occurrences | Severity | Affected Versions |");
    markdown.AppendLine("|---------|-------------|----------|-------------------|");

    foreach (var packageGroup in byPackage)
    {
        var count = packageGroup.Count();
        var severity = packageGroup.First().Severity;
        var versions = string.Join(", ", packageGroup.Select(v => v.Version).Distinct());

        markdown.AppendLine($"| {packageGroup.Key} | {count} | {severity} | {versions} |");
    }

    markdown.AppendLine();
    markdown.AppendLine("## Recommended Actions");
    markdown.AppendLine();
    markdown.AppendLine("1. **High Severity**: Update immediately");
    markdown.AppendLine("2. **Moderate Severity**: Plan update in next sprint");
    markdown.AppendLine("3. **Low Severity**: Update during regular maintenance");
    markdown.AppendLine();
    markdown.AppendLine("### How to Update Packages");
    markdown.AppendLine();
    markdown.AppendLine("```bash");
    markdown.AppendLine("# Update a specific package in a project");
    markdown.AppendLine("dotnet add [project] package [PackageName] --version [LatestVersion]");
    markdown.AppendLine();
    markdown.AppendLine("# For transitive dependencies, add explicit reference");
    markdown.AppendLine("# Example:");
    markdown.AppendLine("# dotnet add package System.Text.Json --version 10.0.0");
    markdown.AppendLine("```");

    File.WriteAllText($"vulnerabilities_{DateTime.Now.ToString("yyyy_MM_dd_HHmmss")}.md", markdown.ToString());
}

int GetSeverityOrder(string severity)
{
    return severity.ToLower() switch
    {
        "high" => 3,
        "moderate" => 2,
        "low" => 1,
        _ => 0
    };
}

class VulnerabilityInfo
{
    public required string Solution { get; set; }
    public required string Project { get; set; }
    public required string PackageName { get; set; }
    public required string Version { get; set; }
    public required string Severity { get; set; }
    public required string AdvisoryUrl { get; set; }
    public required List<string> RootPackages { get; set; }
}
```

## Example Report Output:

---
# NuGet Package Vulnerability Report

**Generated:** 2025-01-01 00:00:00

**Total Vulnerabilities Found:** 4

## Solution: ExampleApp.sln

### moderate Severity (11)

| Package | Version | Project | Root Package(s) | Advisory |
|---------|---------|---------|-----------------|----------|
| Azure.Identity | 1.10.3 | ExampleApp.Web.csproj | dbup | [Link](https://github.com/advisories/GHSA-m5vv-6r4h-3vj9) |
| Azure.Identity | 1.10.3 | ExampleApp.UnitTests.csproj | dbup | [Link](https://github.com/advisories/GHSA-m5vv-6r4h-3vj9) |

### low Severity (3)

| Package | Version | Project | Root Package(s) | Advisory |
|---------|---------|---------|-----------------|----------|
| Microsoft.Identity.Client | 4.56.0 | ExampleApp.UnitTests.csproj | dbup | [Link](https://github.com/advisories/GHSA-x674-v45j-fwxw) |
| Microsoft.Identity.Client | 4.56.0 | ExampleApp.Web.csproj | dbup | [Link](https://github.com/advisories/GHSA-x674-v45j-fwxw) |

## Summary by Package

| Package | Occurrences | Severity | Affected Versions |
|---------|-------------|----------|-------------------|
| Azure.Identity | 2 | moderate | 1.10.3 |
| Microsoft.Identity.Client | 2 | moderate | 4.56.0 |

## Recommended Actions

1. **High Severity**: Update immediately
2. **Moderate Severity**: Plan update in next sprint
3. **Low Severity**: Update during regular maintenance

### How to Update Packages

Ideally, update the root package. If you need to override the vulnerable dependency you can do so as follows, but with an awareness that this can create behavioural changes in your application.

```bash
# Update a specific package in a project
dotnet add [project] package [PackageName] --version [LatestVersion]

# For transitive dependencies, add explicit reference
# Example:
# dotnet add package System.Text.Json --version 10.0.0
```

---

## Summary

Hopefully this post and script help you to manage transitive NuGet package vulnerabilities in your .NET apps.

References:

- https://learn.microsoft.com/en-us/nuget/concepts/auditing-packages#configuring-nuget-audit
- https://learn.microsoft.com/en-us/nuget/concepts/auditing-packages#security-vulnerabilities-found-with-updates
- https://learn.microsoft.com/en-us/nuget/concepts/auditing-packages
