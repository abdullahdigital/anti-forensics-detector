import { ComponentFixture, TestBed } from '@angular/core/testing';

import { FilesystemVisualizer } from './filesystem-visualizer';

describe('FilesystemVisualizer', () => {
  let component: FilesystemVisualizer;
  let fixture: ComponentFixture<FilesystemVisualizer>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      declarations: [FilesystemVisualizer]
    })
    .compileComponents();

    fixture = TestBed.createComponent(FilesystemVisualizer);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
