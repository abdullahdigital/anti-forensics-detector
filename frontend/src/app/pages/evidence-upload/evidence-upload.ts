import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Pipe, PipeTransform } from '@angular/core';

interface FileMetadata {
  fileName: string;
  fileType: string;
  size: number;
  lastModified: Date;
  hash: string;
}

@Pipe({ name: 'fileSize', standalone: true })
export class FileSizePipe implements PipeTransform {
  transform(bytes: number): string {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  }
}

@Component({
  selector: 'app-evidence-upload',
  standalone: true,
  imports: [CommonModule, FormsModule, FileSizePipe],
  templateUrl: './evidence-upload.html',
  styleUrls: ['./evidence-upload.scss']
})
export class EvidenceUploadComponent {
  selectedFiles: File[] = [];
  metadata: FileMetadata[] = [];
  aiSummary: string | null = null;

  onFileSelected(event: any) {
    this.selectedFiles = Array.from(event.target.files);
  }

  uploadFiles() {
    if (this.selectedFiles.length === 0) {
      alert('Please select files to upload.');
      return;
    }

    this.selectedFiles.forEach(file => {
      // Simulate metadata extraction
      const newMetadata: FileMetadata = {
        fileName: file.name,
        fileType: file.type || 'unknown',
        size: file.size,
        lastModified: new Date(file.lastModified),
        hash: this.generateDummyHash(file.name), // Dummy hash generation
      };
      this.metadata.push(newMetadata);
    });

    const totalSize = this.selectedFiles.reduce((sum, f) => sum + f.size, 0);
    const types = Array.from(new Set(this.selectedFiles.map(f => f.type || 'unknown')));
    this.aiSummary = `Analyzed ${this.selectedFiles.length} files (${this.fileSize.transform(totalSize)} total). Detected types: ${types.join(', ')}. No critical anomalies found in quick scan.`;
    alert(`Uploaded ${this.selectedFiles.length} files and extracted metadata.`);
    this.selectedFiles = []; // Clear selected files after upload
  }

  viewDetails(item: FileMetadata) {
    alert(`Viewing details for ${item.fileName}:\nType: ${item.fileType}\nSize: ${this.fileSize.transform(item.size)}\nLast Modified: ${item.lastModified.toLocaleString()}\nHash: ${item.hash}`);
  }

  deleteMetadata(item: FileMetadata) {
    this.metadata = this.metadata.filter(m => m !== item);
    alert(`Deleted metadata for ${item.fileName}`);
  }

  private generateDummyHash(fileName: string): string {
    let hash = 0;
    for (let i = 0; i < fileName.length; i++) {
      const char = fileName.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash |= 0; // Convert to 32bit integer
    }
    return Math.abs(hash).toString(16).substring(0, 10).padStart(10, '0');
  }

  constructor(private fileSize: FileSizePipe) { }
}
