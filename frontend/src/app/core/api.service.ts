import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';

@Injectable({
  providedIn: 'root'
})
export class ApiService {
  private baseUrl = '/api'; // Proxy handles the connection to backend

  constructor(private http: HttpClient) { }

  get<T>(path: string): Observable<T> {
    return this.http.get<T>(`${this.baseUrl}/${path}`);
  }

  post<T>(path: string, body: any): Observable<T> {
    return this.http.post<T>(`${this.baseUrl}/${path}`, body);
  }

  put<T>(path: string, body: any): Observable<T> {
    return this.http.put<T>(`${this.baseUrl}/${path}`, body);
  }

  delete<T>(path: string): Observable<T> {
    return this.http.delete<T>(`${this.baseUrl}/${path}`);
  }

  // Anti-Forensics Analysis Methods
  analyzeFile(filePath: string, detectors?: string[]): Observable<any> {
    return this.post('analysis/file', { file_path: filePath, detectors: detectors });
  }

  analyzeDirectory(directoryPath: string, detectors?: string[]): Observable<any> {
    return this.post('analysis/directory', { directory_path: directoryPath, detectors: detectors });
  }

  uploadFile(file: File, detectors?: string[]): Observable<any> {
    const formData = new FormData();
    formData.append('file', file);
    if (detectors) {
      formData.append('detectors', JSON.stringify(detectors));
    }
    return this.http.post(`${this.baseUrl}/analysis/upload`, formData);
  }
}