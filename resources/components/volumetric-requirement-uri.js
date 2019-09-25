/*
 * This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
 * which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
 *
 */
import {PolymerElement} from '/resources/node_modules/@polymer/polymer/polymer-element.js';
import '/resources/node_modules/@polymer/iron-flex-layout/iron-flex-layout-classes.js';
import '/resources/node_modules/@polymer/iron-ajax/iron-ajax.js';
import '/resources/node_modules/@polymer/iron-form/iron-form.js';
import '/resources/node_modules/@polymer/neon-animation/neon-animated-pages.js';
import '/resources/node_modules/@polymer/paper-listbox/paper-listbox.js';
import '/resources/node_modules/@polymer/paper-icon-button/paper-icon-button.js';
import '/resources/node_modules/@polymer/paper-input/paper-input.js';
import '/resources/node_modules/@polymer/paper-item/paper-item.js';
import '/resources/node_modules/@vaadin/vaadin-upload/vaadin-upload.js';
import {html} from '../node_modules/@polymer/polymer/lib/utils/html-tag.js';

class VolumetricRequirementURI extends PolymerElement {
    static get template() {
        return html`
        <style is="custom-style" include="iron-flex iron-flex-alignment"></style>
        <iron-pages id="URIpages" selected="0">
            <iron-page>
                <div class="layout horizontal">
                    <paper-icon-button icon="language" class="layout self-center" on-tap="toggle"></paper-icon-button>
                    <paper-input class="layout flex" label="{{_friendlyName(element.name)}} ({{element.description}})" value="{{element.default}}" name="vol_{{element.name}}" auto-validate="true" required="{{!element.optional}}" error-message="Invalid value"></paper-input>
                </div>
            </iron-page>
            <iron-page>
                <div class="layout horizontal">
                    <paper-icon-button icon="file-upload" on-tap="toggle"></paper-icon-button>
                    <vaadin-upload></vaadin-upload>
                </div>
            </iron-page>
        </iron-pages>
`;
    }

    static get is() {
        return 'volumetric-requirement-uri';
    }

    static get properties() {
        return {
            'element': {
                type: Object,
                notify: true
            }
        }
    }

    toggle() {
        // keep this as % 1 until we get the file upload functionality working
        this.$.URIpages.selected = (this.$.URIpages.selected + 1) % 2;
    }

    _friendlyName(name) {
        return name.substring(name.lastIndexOf('.') + 1, name.length)
    }
}

window.customElements.define(VolumetricRequirementURI.is, VolumetricRequirementURI);
