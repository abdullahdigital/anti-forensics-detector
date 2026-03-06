import { Component, signal } from '@angular/core';
import { NavbarComponent } from './components/navbar/navbar';
import { FooterComponent } from './components/footer/footer';
import { RouterModule, Router, ActivatedRoute, NavigationEnd } from '@angular/router';
import { CommonModule } from '@angular/common';
import { Title } from '@angular/platform-browser';
import { filter, map } from 'rxjs/operators';

@Component({
  selector: 'app-root',
  templateUrl: './app.html',
  standalone: true,
  styleUrl: './app.scss',
  imports: [
    NavbarComponent,
    FooterComponent,
    CommonModule,
    RouterModule
  ]
})
export class App {
  protected readonly title = signal('frontend');

  constructor(private router: Router, private activatedRoute: ActivatedRoute, private titleService: Title) {
    this.router.events.pipe(
      filter(event => event instanceof NavigationEnd),
      map(() => {
        let child = this.activatedRoute.firstChild;
        while (child) {
          if (child.firstChild) {
            child = child.firstChild;
          } else if (child.snapshot.data && child.snapshot.data['title']) {
            return child.snapshot.data['title'];
          } else {
            return null;
          }
        }
        return null;
      })
    ).subscribe((title: string | null) => {
      if (title) {
        this.titleService.setTitle(title);
      }
    });
  }
}
