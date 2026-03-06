import { Component, AfterViewInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterModule } from '@angular/router';

@Component({
  selector: 'app-navbar',
  standalone: true,
  imports: [CommonModule, RouterModule],
  templateUrl: './navbar.html',
  styleUrls: ['./navbar.scss']
})
export class NavbarComponent implements AfterViewInit {

  ngAfterViewInit() {
    const button = document.getElementById('navbar-toggle');
    const menu = document.getElementById('navbar-links');

    if (button && menu) {
      button.addEventListener('click', () => {
        menu.classList.toggle('hidden');
      });
    }
  }
}