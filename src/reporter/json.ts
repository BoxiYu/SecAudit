import { ScanResult } from '../types.js';

export function reportJSON(result: ScanResult): void {
  console.log(JSON.stringify(result, null, 2));
}
