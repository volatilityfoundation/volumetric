/*
 * This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
 * which is available at https://www.volatilityfoundation.org/license/vsl_v1.0
 *
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
