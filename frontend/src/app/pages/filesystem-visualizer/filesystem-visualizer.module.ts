import { NgModule } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FilesystemVisualizer } from './filesystem-visualizer/filesystem-visualizer';



@NgModule({
  declarations: [
    FilesystemVisualizer
  ],
  imports: [
    CommonModule
  ]
})
export class FilesystemVisualizerModule { }
