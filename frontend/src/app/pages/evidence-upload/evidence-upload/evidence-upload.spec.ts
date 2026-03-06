import { ComponentFixture, TestBed } from '@angular/core/testing';

import { EvidenceUpload } from './evidence-upload';

describe('EvidenceUpload', () => {
  let component: EvidenceUpload;
  let fixture: ComponentFixture<EvidenceUpload>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      declarations: [EvidenceUpload]
    })
    .compileComponents();

    fixture = TestBed.createComponent(EvidenceUpload);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
