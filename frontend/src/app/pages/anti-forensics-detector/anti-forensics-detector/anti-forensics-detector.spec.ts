import { ComponentFixture, TestBed } from '@angular/core/testing';

import { AntiForensicsDetector } from './anti-forensics-detector';

describe('AntiForensicsDetector', () => {
  let component: AntiForensicsDetector;
  let fixture: ComponentFixture<AntiForensicsDetector>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      declarations: [AntiForensicsDetector]
    })
    .compileComponents();

    fixture = TestBed.createComponent(AntiForensicsDetector);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
