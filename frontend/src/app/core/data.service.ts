import { Injectable } from '@angular/core';
import { BehaviorSubject, Observable } from 'rxjs';

@Injectable({
  providedIn: 'root'
})
export class DataService {
  private evidenceDataSubject = new BehaviorSubject<any>(null);
  evidenceData$: Observable<any> = this.evidenceDataSubject.asObservable();

  constructor() { }

  setEvidenceData(data: any) {
    this.evidenceDataSubject.next(data);
  }

  getEvidenceData(): any {
    return this.evidenceDataSubject.getValue();
  }
}