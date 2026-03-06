import { Component, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { HttpClientModule, HttpErrorResponse } from '@angular/common/http';
import { ApiService } from '../../core/api.service';

interface AnalysisResult {
  indicator: string;
  description: string;
  severity: 'Low' | 'Medium' | 'High' | 'Critical';
  confidence: number;
  details: string;
  content_preview?: string;
}

interface StreamData {
  name: string;
  size_bytes: number;
  stream_type: string;
  risk_score: number;
  content_preview?: string;
  is_executable?: boolean;
  is_encrypted?: boolean;
  hash_md5?: string;
  hash_sha256?: string;
  entropy?: number;
  creation_time?: string;
  modification_time?: string;
}

interface RiskAssessment {
  risk_level: 'low' | 'medium' | 'high' | 'critical';
  score: number;
  description: string;
  details?: {
    total_streams: number;
    critical_streams: number;
    high_risk_streams: number;
    medium_risk_streams: number;
    low_risk_streams: number;
    executable_streams: number;
    encrypted_streams: number;
    total_size_bytes: number;
    total_size_human: string;
  };
}

interface ScanSummary {
  total_files_scanned: number;
  files_with_ads: number;
  total_ads_streams: number;  // ADD THIS
  scan_timestamp: string;
}

interface ApiResponse {
  success: boolean;
  filename?: string;
  data: any; // Keep generic to support both old ADS structure and new general structure
  detail?: string;
  selected_detectors?: string[];
  message?: string;
  error?: string;
}

interface DetectorOption {
  name: string;
  value: string;
  category: string;
  subOptions?: DetectorOption[];
}

@Component({
  selector: 'app-anti-forensics-detector',
  standalone: true,
  imports: [CommonModule, FormsModule, HttpClientModule],
  templateUrl: './anti-forensics-detector.html',
  styleUrls: ['./anti-forensics-detector.scss']
})
export class AntiForensicsDetectorComponent {
  analysisPath: string = '';

  // Separate selection for ADS methods
  availableDetectors: DetectorOption[] = [
    {
      name: 'File Masquerading (Extension Check)',
      value: 'masquerade_detection',
      category: 'file_system'
    },
    {
      name: 'Alternate Data Streams (ADS)',
      value: 'ads_detection',
      category: 'file_system',
      subOptions: [
        { name: 'Xattr Detection', value: 'xattr', category: 'ads_method' },
        { name: 'Pattern Matching', value: 'pattern', category: 'ads_method' }
      ]
    },
    { name: 'Data Wiping', value: 'data_wiping_detection', category: 'file_system' },
    { name: 'Encryption', value: 'encryption_detection', category: 'content' },
    { name: 'Fake Metadata', value: 'fake_metadata_detection', category: 'metadata' },
    { name: 'Hidden Files', value: 'hidden_file_detection', category: 'file_system' },
    { name: 'Log Tampering', value: 'log_tampering_detection', category: 'logs' },
    { name: 'Steganography', value: 'steganography_detection', category: 'content' },
    { name: 'Suspicious Rename', value: 'suspicious_rename_detection', category: 'file_system' },
    { name: 'Timestomp', value: 'timestomping_detection', category: 'metadata' },
  ];

  // Separate selection for ADS methods
  selectedDetectors: string[] = [];
  selectedADSMethods: string[] = ['powershell']; // Default ADS method
  analysisResults: AnalysisResult[] = [];
  riskAssessment: RiskAssessment | null = null;
  recommendations: string[] = [];
  summary: string = '';
  errorMessage: string = '';
  selectedFile: File | null = null;
  isLoading: boolean = false;
  isScanningDirectory: boolean = false;

  private apiService = inject(ApiService);

  // PUBLIC METHODS FOR TEMPLATE
  formatSize(bytes: number): string {
    if (bytes === 0 || bytes === undefined || isNaN(bytes)) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    // Handle cases where byte size is small but non-zero causing negative index or similar
    if (i < 0) return bytes + ' B';
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + (sizes[i] || 'B');
  }

  showDetails(result: AnalysisResult): void {
    // Keep detailed alert for now as it contains raw JSON, or consider a modal later. 
    // User specifically complained about "Analysis complete" popup.
    alert(`Stream Details:\n\n${result.details
      }`);
  }

  onFileSelected(event: Event): void {
    const element = event.target as HTMLInputElement;
    if (element.files && element.files.length > 0) {
      this.selectedFile = element.files[0];
      this.analysisPath = this.selectedFile.name;
    } else {
      this.selectedFile = null;
    }
  }

  onDetectorChange(detectorValue: string, event: Event): void {
    const isChecked = (event.target as HTMLInputElement).checked;
    if (isChecked) {
      if (!this.selectedDetectors.includes(detectorValue)) {
        this.selectedDetectors.push(detectorValue);
      }
    } else {
      this.selectedDetectors = this.selectedDetectors.filter(d => d !== detectorValue);

      // If ADS detector is deselected, clear ADS methods
      if (detectorValue === 'ads_detection') {
        this.selectedADSMethods = [];
      }
    }
  }

  onADSMethodChange(methodValue: string, event: Event): void {
    const isChecked = (event.target as HTMLInputElement).checked;
    if (isChecked) {
      if (!this.selectedADSMethods.includes(methodValue)) {
        this.selectedADSMethods.push(methodValue);
      }
    } else {
      this.selectedADSMethods = this.selectedADSMethods.filter(m => m !== methodValue);
    }
  }

  isADSSelected(): boolean {
    return this.selectedDetectors.includes('ads_detection');
  }

  clearSelection(): void {
    this.selectedDetectors = [];
    this.selectedADSMethods = ['powershell'];
    this.analysisResults = [];
    this.riskAssessment = null;
    this.recommendations = [];
    this.summary = '';
    this.errorMessage = '';
    this.analysisPath = '';
    this.selectedFile = null;
    this.isScanningDirectory = false;

    // Reset file input
    const fileInput = document.getElementById('fileUpload') as HTMLInputElement;
    if (fileInput) {
      fileInput.value = '';
    }
  }

  scanType: 'file' | 'directory' = 'file';

  onScanTypeChange(type: 'file' | 'directory'): void {
    this.scanType = type;
    this.analysisPath = '';
    this.selectedFile = null;
    this.clearSelection();
  }

  runAnalysis(): void {
    // Validate input
    if (this.scanType === 'file' && !this.selectedFile && !this.analysisPath.trim()) {
      this.errorMessage = 'Please provide a file or file path.';
      return;
    }

    if (this.scanType === 'directory' && !this.analysisPath.trim()) {
      this.errorMessage = 'Please enter a directory path.';
      return;
    }

    // Note: The new backend runs ALL detectors automatically. 
    // We keep the selection UI specific logic for filtered views if needed, 
    // but the API call will trigger everything currently.

    this.analysisResults = [];
    this.riskAssessment = null;
    this.recommendations = [];
    this.summary = '';
    this.errorMessage = '';
    this.isLoading = true;

    if (this.scanType === 'file') {
      if (this.selectedFile) {
        this.uploadAndAnalyzeFile();
      } else if (this.analysisPath.trim()) {
        this.analyzeFileOnServer();
      } else {
        this.errorMessage = 'Please provide a file or file path.';
        this.isLoading = false;
      }
    } else {
      this.analyzeDirectorypath();
    }
  }

  private uploadAndAnalyzeFile(): void {
    this.apiService.uploadFile(this.selectedFile!, this.selectedDetectors).subscribe({
      next: (response) => {
        this.handleApiResponse(response);
      },
      error: (error: HttpErrorResponse) => {
        this.handleApiError(error);
      }
    });
  }

  private analyzeFileOnServer(): void {
    // Pass selected detectors (or undefined if none selected, implying all - though backend implementation might key off empty list too)
    // Based on logic, if selectedDetectors is empty, maybe run all? Or force selection?
    // Current UI implies "check what you want". Empty usually means nothing or all. 
    // Let's pass what's in the array. If array is empty, backend logic above in Python handles it?
    // Wait, backend logic: if selected_detectors and len > 0. So if empty list, it runs ALL.
    // If user explicitly unchecks everything, they might expect nothing.
    // But usually "Select None" means "Run All" in some tools, or invalid state.
    // Let's assume if they select specific ones, we send them. If empty, we send empty list and backend runs all?
    // Looking at my backend code: "if selected_detectors and len(selected_detectors) > 0".
    // So if I send [], it runs all. 
    // If I want to support "run nothing", I need to change backend or not call API.
    // But "run nothing" is useless.
    // So if selectedDetectors is empty, it runs ALL.

    // However, the issue was user checks ONE and gets ALL.
    // So I must make sure I send the non-empty list.

    this.apiService.analyzeFile(this.analysisPath.trim(), this.selectedDetectors).subscribe({
      next: (response: ApiResponse) => {
        this.handleApiResponse(response);
      },
      error: (error: HttpErrorResponse) => {
        this.handleApiError(error);
      }
    });
  }

  private analyzeDirectorypath(): void {
    this.apiService.analyzeDirectory(this.analysisPath.trim(), this.selectedDetectors).subscribe({
      next: (response: ApiResponse) => {
        this.handleApiResponse(response);
      },
      error: (error: HttpErrorResponse) => {
        this.handleApiError(error);
      }
    });
  }

  private handleApiResponse(response: ApiResponse): void {
    this.isLoading = false;

    if (response.success && response.data) {
      const data = response.data;

      // Check if this is a directory report
      if (data.detailed_findings) {
        this.handleDirectoryResponse(data);
      } else {
        // Single file response
        this.handleFileResponse(data);
      }

    } else {
      const errorMsg = response.detail || response.data?.error || response.error || response.message || 'Unknown error';
      this.errorMessage = `Analysis failed: ${errorMsg} `;
    }
  }

  private handleDirectoryResponse(data: any): void {
    this.summary = `Analyzed ${data.summary?.total_files_analyzed || 0} files.Found ${data.summary?.total_anomalies_detected || 0} anomalies.`;
    this.recommendations = [`Review the ${data.summary?.suspicious_files?.length || 0} suspicious files identified.`];

    // Flatten findings for display table
    if (data.detailed_findings) {
      data.detailed_findings.forEach((file: any) => {
        if (file.anomalies_found && file.anomalies_found.length > 0) {
          file.anomalies_found.forEach((anomaly: any) => {
            this.analysisResults.push({
              indicator: file.file_path,
              description: `${anomaly.detector} - ${anomaly.reasons?.join(', ') || 'Suspicious activity detected'} `,
              severity: this.calculateSeverity(anomaly.suspicion_score * 100),
              confidence: anomaly.suspicion_score * 100,
              details: JSON.stringify(anomaly.details, null, 2),
              content_preview: ''
            });
          });
        }
      });
    }

    if (this.analysisResults.length === 0) {
      this.summary = `Analysis complete.No anomalies found in ${data.summary?.total_files_analyzed} files.`;
    } else {
      this.summary = `Analysis complete.Found anomalies in directory.`;
    }
  }

  private handleFileResponse(data: any): void {
    // Check overall score
    if (data.overall_suspicion_score !== undefined) {
      this.summary = `File Analysis Complete.Overall Suspicion Score: ${(data.overall_suspicion_score * 100).toFixed(1)}% `;
    }

    // Map detector results to UI
    const processedKeys: string[] = [];
    for (const [key, result] of Object.entries(data)) {
      if (key === 'file_path' || key === 'overall_suspicion_score' || key === 'ai_confidence_score') continue;

      processedKeys.push(key);
      try {
        const res = result as any;

        // Check for specific error in detector result
        if (res.error) {
          this.analysisResults.push({
            indicator: key.replace('_detection', '').replace('_detector', '').replace(/_/g, ' ').toUpperCase(),
            description: `Error: ${res.error} `,
            severity: 'High',
            confidence: 100,
            details: JSON.stringify(res, null, 2),
            content_preview: 'Analysis Failed'
          });
          continue;
        }

        // Special handling for ADS results to show detailed streams
        if (key === 'ads_detection' && (res.ads_found || res.ads_detected) && res.streams) {
          res.streams.forEach((stream: any) => {
            this.analysisResults.push({
              indicator: stream.name || 'ADS Stream',
              description: `${stream.stream_type} | Size: ${this.formatSize(stream.size_bytes)} `,
              severity: this.calculateSeverity(stream.risk_score),
              confidence: stream.risk_score,
              details: this.formatStreamDetails(stream),
              content_preview: stream.content_preview
            });
          });
          continue; // processed ADS, move to next detector
        }

        // Check for suspicious flags (Backend keys mapped to Fronted check)
        const isSuspicious = res.is_log_tampering_suspected ||
          res.is_suspicious_rename ||
          res.is_timestamp_anomaly_suspected ||
          res.is_steganography_suspected ||
          res.is_fake_metadata_suspected ||
          res.is_data_wiping_suspected ||
          res.is_encryption_suspected ||
          res.is_hidden_file_suspected ||
          res.ids_detected ||
          res.is_masqueraded || // New Masquerade Detection
          res.is_timestomped || // Corrected Backend Key
          res.is_timestomping_suspected; // Legacy/Fallback

        if (isSuspicious) {
          let reasons = res.reasons || res.suspicion_reasons || [];

          this.analysisResults.push({
            indicator: key.replace('_detection', '').replace('_detector', '').replace(/_/g, ' ').toUpperCase(),
            description: (Array.isArray(reasons) && reasons.length > 0 ? reasons[0].substring(0, 30) + (reasons[0].length > 30 ? '...' : '') : 'Anomaly') + ' | Size: N/A',
            severity: this.calculateSeverity((res.suspicion_score || 0) * 100),
            confidence: (res.suspicion_score || 0) * 100,
            details: JSON.stringify(res, null, 2),
            content_preview: ''
          });
        }
      } catch (e) {
        console.error(`Error processing results for detector ${key}: `, e);
      }
    }

    if (this.analysisResults.length === 0) {
      this.summary = `Analysis complete.Processed keys: [${processedKeys.join(', ')}].No suspicious indicators found.`;
    } else {
      this.summary = `Analysis complete.Processed: [${processedKeys.join(', ')}].`;
    }
  }

  private handleADSResponse(data: any): void {
    // Check if ADS were found
    if (!data.ads_found) {
      const targetName = this.selectedFile ? this.selectedFile.name : this.analysisPath;
      this.summary = `No ADS streams found in ${targetName} `;
      this.recommendations = data.recommendations || ['No action required'];
      // alert(`Analysis complete for ${ targetName }.No ADS streams found.`);
      return;
    }

    // Process streams if found
    if (data.streams && data.streams.length > 0) {
      this.analysisResults = data.streams.map((stream: StreamData) => ({
        indicator: stream.name,
        description: `${stream.stream_type} | Size: ${this.formatSize(stream.size_bytes)} `,
        severity: this.calculateSeverity(stream.risk_score),
        confidence: stream.risk_score,
        details: this.formatStreamDetails(stream),
        content_preview: stream.content_preview
      }));
    }

    // Store additional data
    this.riskAssessment = data.risk_assessment || null;
    this.recommendations = data.recommendations || [];
    this.summary = data.summary || `Found ${data.total_streams || 0} ADS streams`;

    const targetName = this.selectedFile ? this.selectedFile.name : this.analysisPath;
    this.summary = `Analysis complete for ${targetName}.Found ${data.total_streams || 0} ADS streams.`;
  }

  private handleOtherDetectorResponse(data: any): void {
    // TODO: Implement handling for other detectors
    // This will depend on how your other detectors return data
    alert('Other detector analysis completed (not yet implemented fully).');
  }

  private handleApiError(error: HttpErrorResponse): void {
    this.isLoading = false;
    console.error('API Error:', error);

    if (error.status === 0) {
      this.errorMessage = 'Cannot connect to the backend server. Please make sure the Flask server is running on port 5000.';
    } else if (error.status === 400) {
      const errorMsg = error.error?.detail || error.error?.error || 'Invalid request';
      this.errorMessage = `Bad request: ${errorMsg} `;
    } else if (error.status === 404) {
      this.errorMessage = 'File or endpoint not found. Please check the path and ensure the API is running.';
    } else if (error.status === 500) {
      const errorMsg = error.error?.detail || error.error?.error || 'Internal server error';
      this.errorMessage = `Server error: ${errorMsg} `;
    } else {
      this.errorMessage = `Error ${error.status}: ${error.message} `;
    }
  }

  private calculateSeverity(riskScore: number): 'Low' | 'Medium' | 'High' | 'Critical' {
    if (riskScore >= 80) {
      return 'Critical';
    } else if (riskScore >= 60) {
      return 'High';
    } else if (riskScore >= 30) {
      return 'Medium';
    } else {
      return 'Low';
    }
  }

  private formatStreamDetails(stream: StreamData): string {
    let details = '';

    details += `Name: ${stream.name} \n`;
    details += `Type: ${stream.stream_type} \n`;
    details += `Size: ${this.formatSize(stream.size_bytes)} \n`;
    details += `Risk Score: ${stream.risk_score}/100\n`;

    if (stream.is_executable !== undefined) {
      details += `Executable: ${stream.is_executable ? 'Yes' : 'No'}\n`;
    }

    if (stream.is_encrypted !== undefined) {
      details += `Encrypted: ${stream.is_encrypted ? 'Yes' : 'No'}\n`;
    }

    if (stream.entropy !== undefined) {
      details += `Entropy: ${stream.entropy.toFixed(2)}\n`;
    }

    if (stream.hash_md5) {
      details += `MD5: ${stream.hash_md5}\n`;
    }

    if (stream.hash_sha256) {
      details += `SHA256: ${stream.hash_sha256}\n`;
    }

    if (stream.creation_time) {
      details += `Created: ${new Date(stream.creation_time).toLocaleString()}\n`;
    }

    if (stream.modification_time) {
      details += `Modified: ${new Date(stream.modification_time).toLocaleString()}\n`;
    }

    return details;
  }

  selectAllDetectors(event: Event): void {
    const isChecked = (event.target as HTMLInputElement).checked;
    if (isChecked) {
      this.selectedDetectors = this.availableDetectors.map(detector => detector.value);
      // If ADS is selected, also select default methods
      if (this.isADSSelected()) {
        this.selectedADSMethods = ['powershell'];
      }
    } else {
      this.selectedDetectors = [];
      this.selectedADSMethods = [];
    }
  }

  selectAllADSMethods(event: Event): void {
    const isChecked = (event.target as HTMLInputElement).checked;
    if (isChecked) {
      const adsDetector = this.availableDetectors.find(d => d.value === 'ads_detector');
      if (adsDetector?.subOptions) {
        this.selectedADSMethods = adsDetector.subOptions.map(opt => opt.value);
      }
    } else {
      this.selectedADSMethods = [];
    }
  }

  isAllSelected(): boolean {
    return this.selectedDetectors.length === this.availableDetectors.length &&
      this.availableDetectors.length > 0;
  }

  isAllADSMethodsSelected(): boolean {
    const adsDetector = this.availableDetectors.find(d => d.value === 'ads_detector');
    return adsDetector?.subOptions ?
      this.selectedADSMethods.length === adsDetector.subOptions.length : false;
  }

  // Test backend connection
  testBackendConnection(): void {
    this.apiService.get<{ status: string, service: string }>('ads/health').subscribe({
      next: (response) => {
        alert(`✅ Backend is ${response.status} (${response.service})`);
      },
      error: (error: HttpErrorResponse) => {
        if (error.status === 0) {
          alert('❌ Cannot connect to backend. Make sure Flask server is running on port 5000.');
        } else {
          alert(`❌ Backend error: ${error.message}`);
        }
      }
    });
  }

  // Test ADS creation
  createTestADS(): void {
    this.apiService.get<ApiResponse>('ads/test/create').subscribe({
      next: (response) => {
        if (response.success) {
          alert(`✅ ${response.message}`);
        } else {
          const errorMsg = response.detail || response.error || 'Unknown error';
          alert(`❌ Failed to create test ADS: ${errorMsg}`);
        }
      },
      error: (error: HttpErrorResponse) => {
        alert(`❌ Error creating test ADS: ${error.message}`);
      }
    });
  }

  // Get directory statistics
  getDirectoryStats(): void {
    if (!this.analysisPath.trim()) {
      alert('Please enter a directory path first.');
      return;
    }

    this.apiService.get<ApiResponse>(`ads/stats?directory=${encodeURIComponent(this.analysisPath.trim())}`).subscribe({
      next: (response) => {
        if (response.success && response.data?.scan_summary) {
          const scanSummary = response.data.scan_summary;
          alert(`Directory Scan Results:\n\n` +
            `Total Files Scanned: ${scanSummary.total_files_scanned}\n` +
            `Files with ADS: ${scanSummary.files_with_ads}\n` +
            `Total ADS Streams: ${scanSummary.total_ads_streams}`);
        } else {
          const errorMsg = response.detail || response.error || 'Unknown error';
          alert(`❌ Failed to get directory stats: ${errorMsg}`);
        }
      },
      error: (error: HttpErrorResponse) => {
        alert(`❌ Error getting directory stats: ${error.message}`);
      }
    });
  }

  generateReport(): void {
    if (this.analysisResults.length === 0) {
      alert('No analysis results to generate a report from.');
      return;
    }

    const report = this.createReport();
    console.log('Report generated:', report);
    this.downloadReport(report);
  }

  private createReport(): string {
    const timestamp = new Date().toISOString();
    const target = this.selectedFile ? this.selectedFile.name : this.analysisPath;

    let report = `=== ANTI-FORENSICS ANALYSIS REPORT ===\n\n`;
    report += `Generated: ${timestamp}\n`;
    report += `Target: ${target}\n`;
    report += `Platform: ${navigator.platform}\n`;
    report += `Detectors Used: ${this.selectedDetectors.join(', ')}\n`;
    if (this.isADSSelected()) {
      report += `ADS Methods: ${this.selectedADSMethods.join(', ')}\n`;
    }
    report += `Scan Type: ${this.isScanningDirectory ? 'Directory Scan' : 'File Scan'}\n`;
    report += `Timestamp: ${new Date().toLocaleString()}\n\n`;

    if (this.summary) {
      report += `SUMMARY:\n`;
      report += `${this.summary}\n\n`;
    }

    if (this.riskAssessment) {
      report += `RISK ASSESSMENT:\n`;
      report += `  Level: ${this.riskAssessment.risk_level.toUpperCase()}\n`;
      report += `  Score: ${this.riskAssessment.score}/100\n`;
      report += `  Description: ${this.riskAssessment.description}\n`;

      if (this.riskAssessment.details) {
        const details = this.riskAssessment.details;
        report += `  Details:\n`;
        report += `    Total Streams: ${details.total_streams}\n`;
        report += `    Critical: ${details.critical_streams}\n`;
        report += `    High Risk: ${details.high_risk_streams}\n`;
        report += `    Medium Risk: ${details.medium_risk_streams}\n`;
        report += `    Low Risk: ${details.low_risk_streams}\n`;
        report += `    Executable: ${details.executable_streams}\n`;
        report += `    Encrypted: ${details.encrypted_streams}\n`;
        report += `    Total Size: ${details.total_size_human}\n`;
      }
      report += `\n`;
    }

    if (this.recommendations.length > 0) {
      report += `RECOMMENDATIONS:\n`;
      this.recommendations.forEach(rec => report += `  • ${rec}\n`);
      report += `\n`;
    }

    report += `DETAILED FINDINGS (${this.analysisResults.length} total):\n`;
    report += `-`.repeat(80) + `\n`;

    this.analysisResults.forEach((result, index) => {
      report += `FINDING #${index + 1}\n`;
      report += `Indicator: ${result.indicator}\n`;
      report += `Severity: ${result.severity}\n`;
      report += `Confidence: ${result.confidence}%\n`;
      report += `Description: ${result.description}\n`;

      if (result.content_preview) {
        report += `Content Preview: ${result.content_preview}\n`;
      }

      report += `Details:\n${result.details}\n`;
      report += `-`.repeat(80) + `\n`;
    });

    report += `\n=== END OF REPORT ===\n`;
    return report;
  }

  private downloadReport(reportContent: string): void {
    const blob = new Blob([reportContent], { type: 'text/plain;charset=utf-8' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
    const targetName = this.selectedFile ?
      this.selectedFile.name.replace(/\.[^/.]+$/, "") :
      this.analysisPath.replace(/[^a-z0-9]/gi, '_').slice(0, 50);
    const filename = `anti-forensics-report-${targetName}-${timestamp}.txt`;

    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    window.URL.revokeObjectURL(url);

    alert(`Report '${filename}' has been downloaded.`);
  }

  // Helper method to display risk level with color
  getSeverityClass(severity: string): string {
    switch (severity.toLowerCase()) {
      case 'critical': return 'severity-critical';
      case 'high': return 'severity-high';
      case 'medium': return 'severity-medium';
      case 'low': return 'severity-low';
      default: return '';
    }
  }
}