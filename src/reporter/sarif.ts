import { ScanResult, Severity } from '../types.js';

const SARIF_SEVERITY: Record<Severity, string> = {
  [Severity.Critical]: 'error',
  [Severity.High]: 'error',
  [Severity.Medium]: 'warning',
  [Severity.Low]: 'note',
  [Severity.Info]: 'note',
};

export function reportSARIF(result: ScanResult): void {
  const sarif = {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'secaudit',
            version: '0.1.0',
            informationUri: 'https://github.com/user/secaudit',
            rules: [...new Set(result.findings.map((f) => f.rule))].map((ruleId) => {
              const finding = result.findings.find((f) => f.rule === ruleId)!;
              return {
                id: ruleId,
                shortDescription: { text: finding.message },
                defaultConfiguration: {
                  level: SARIF_SEVERITY[finding.severity],
                },
              };
            }),
          },
        },
        results: result.findings.map((f) => ({
          ruleId: f.rule,
          level: SARIF_SEVERITY[f.severity],
          message: { text: f.message },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: f.file },
                region: {
                  startLine: f.line,
                  startColumn: f.column,
                },
              },
            },
          ],
        })),
      },
    ],
  };

  console.log(JSON.stringify(sarif, null, 2));
}
