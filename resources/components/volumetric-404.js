/**
 @license
 Copyright (c) 2016 The Polymer Project Authors. All rights reserved.
 This code may only be used under the BSD style license found at http://polymer.github.io/LICENSE.txt
 The complete set of authors may be found at http://polymer.github.io/AUTHORS.txt
 The complete set of contributors may be found at http://polymer.github.io/CONTRIBUTORS.txt
 Code distributed by Google as part of the polymer project is also
 subject to an additional IP rights grant found at http://polymer.github.io/PATENTS.txt
 */
import {PolymerElement} from '/resources/node_modules/@polymer/polymer/polymer-element.js';

import {html} from '/resources/node_modules/@polymer/polymer/lib/utils/html-tag.js';

class Volumetric404 extends PolymerElement {
    static get template() {
        return html`
    <style>
      :host {
          display: block;

          padding: 10px 20px;
      }
    </style>

        Page not found. <a href="[[rootPath]]">Head back to home.</a>
`;
    }

    static get is() {
        return 'volumetric-404';
    }

    static get properties() {
        return {
            // This shouldn't be neccessary, but the Analyzer isn't picking up
            // Polymer.Element#rootPath
            rootPath: String,
        };
    }
}

window.customElements.define(Volumetric404.is, Volumetric404);
