// Harmless lab stub for case IR-2026-FIN042, step 1 (T1059.001).
//
// This is NOT malware. It writes one marker file and prints one line, then exits.
// It stands in for a first-stage payload so the lab has a real PE on disk whose
// SHA256 can be promoted to a block-and-remediate custom indicator in the response
// phase. The file is benign by itself; it is blocked later only because we add its
// hash to the indicator by hand - that is exactly what the block-indicator step
// demonstrates. Do not add any network, persistence or process-injection behaviour
// here; the chain's malicious behaviour lives in steps 2-4, run with Atomic Red Team.

using System;
using System.IO;

internal static class LabStub
{
    private static void Main()
    {
        string marker = Path.Combine(Path.GetTempPath(), "ir-fin042-stub-ran.txt");
        File.WriteAllText(
            marker,
            "IR-2026-FIN042 lab stub executed at " + DateTime.UtcNow.ToString("o") + Environment.NewLine);
        Console.WriteLine("IR-2026-FIN042 lab stub ran. Benign portfolio-lab artifact.");
    }
}
