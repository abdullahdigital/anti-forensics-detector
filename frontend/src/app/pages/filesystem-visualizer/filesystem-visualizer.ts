import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { FileSizePipe } from '../evidence-upload/evidence-upload';

@Component({
  selector: 'app-filesystem-visualizer',
  standalone: true,
  imports: [CommonModule, FormsModule, FileSizePipe],
  templateUrl: './filesystem-visualizer.html',
  styleUrls: ['./filesystem-visualizer.scss']
})
export class FilesystemVisualizerComponent {
  selectedFile: { name: string; type: string; size: number; modified: string; hex: string[] } | null = null;
  tree: Array<{ name: string; type: 'folder' | 'file'; children?: any[]; size?: number; modified?: string; hex?: string[] }> = [
    {
      name: 'Root',
      type: 'folder',
      children: [
        {
          name: 'Users',
          type: 'folder',
          children: [
            {
              name: 'JohnDoe',
              type: 'folder',
              children: [
                { name: 'document.docx', type: 'file', size: 24576, modified: '2025-10-01 12:03', hex: ['4D', '5A', '90', '00', '03', '00', '00', '00'] },
                { name: 'photo.jpg', type: 'file', size: 512000, modified: '2025-10-02 08:22', hex: ['FF', 'D8', 'FF', 'E0', '00', '10', '4A', '46'] }
              ]
            },
            {
              name: 'JaneSmith',
              type: 'folder',
              children: [
                { name: 'report.pdf', type: 'file', size: 102400, modified: '2025-09-28 17:45', hex: ['25', '50', '44', '46', '2D', '31', '2E', '35'] }
              ]
            }
          ]
        },
        {
          name: 'System',
          type: 'folder',
          children: [
            { name: 'kernel.sys', type: 'file', size: 2048000, modified: '2025-08-10 06:12', hex: ['7F', '45', '4C', '46', '02', '01', '01', '00'] }
          ]
        }
      ]
    }
  ];

  selectFile(node: any) {
    if (node.type !== 'file') return;
    this.selectedFile = {
      name: node.name,
      type: 'file',
      size: node.size,
      modified: node.modified,
      hex: node.hex || []
    };
  }
}
