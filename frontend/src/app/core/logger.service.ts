import { Injectable } from '@angular/core';

@Injectable({
  providedIn: 'root'
})
export class LoggerService {

  constructor() { }

  log(message: string, ...optionalParams: any[]) {
    console.log(`[ForenX Log] ${message}`, ...optionalParams);
  }

  error(message: string, ...optionalParams: any[]) {
    console.error(`[ForenX Error] ${message}`, ...optionalParams);
  }

  warn(message: string, ...optionalParams: any[]) {
    console.warn(`[ForenX Warn] ${message}`, ...optionalParams);
  }
}