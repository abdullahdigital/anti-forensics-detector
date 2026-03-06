import { NgModule } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { HttpClientModule } from '@angular/common/http';
import { AntiForensicsDetector } from './anti-forensics-detector/anti-forensics-detector';

@NgModule({
  declarations: [
    AntiForensicsDetector
  ],
  imports: [
    CommonModule,
    FormsModule,           // ADD THIS - for ngModel
    HttpClientModule       // ADD THIS - for HttpClient
  ],
  exports: [
    AntiForensicsDetector
  ]
})
export class AntiForensicsDetectorModule { }