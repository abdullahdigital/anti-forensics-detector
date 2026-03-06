import { Routes } from '@angular/router';
import { HomeComponent } from './pages/home/home';
import { DashboardComponent } from './pages/dashboard/dashboard';
import { EvidenceUploadComponent } from './pages/evidence-upload/evidence-upload';
import { FilesystemVisualizerComponent } from './pages/filesystem-visualizer/filesystem-visualizer';
import { AntiForensicsDetectorComponent } from './pages/anti-forensics-detector/anti-forensics-detector';
import { ReportGeneratorComponent } from './pages/report-generator/report-generator';

export const routes: Routes = [
  { path: '', redirectTo: '/home', pathMatch: 'full' },
  { path: 'home', component: HomeComponent, title: 'Home' },
  { path: 'dashboard', component: DashboardComponent, title: 'Dashboard' },
  { path: 'evidence-upload', component: EvidenceUploadComponent, title: 'Evidence Upload' },
  { path: 'filesystem-visualizer', component: FilesystemVisualizerComponent, title: 'Filesystem Visualizer' },
  { path: 'anti-forensics-detector', component: AntiForensicsDetectorComponent, title: 'Anti-Forensics Detector' },
  { path: 'report-generator', component: ReportGeneratorComponent, title: 'Report Generator' },
  { path: '**', redirectTo: '/home', title: 'Page Not Found' } // Wildcard route for a 404 page
];