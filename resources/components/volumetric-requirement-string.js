import {Element} from '/resources/node_modules/@polymer/polymer/polymer-element.js';
import '/resources/node_modules/@polymer/iron-flex-layout/iron-flex-layout-classes.js';
import '/resources/node_modules/@polymer/iron-ajax/iron-ajax.js';
import '/resources/node_modules/@polymer/iron-form/iron-form.js';
import '/resources/node_modules/@polymer/paper-listbox/paper-listbox.js';
import '/resources/node_modules/@polymer/paper-icon-button/paper-icon-button.js';
import '/resources/node_modules/@polymer/paper-input/paper-input.js';
import '/resources/node_modules/@polymer/paper-item/paper-item.js';
import {html} from '../node_modules/@polymer/polymer/lib/utils/html-tag.js';

class VolumetricRequirementString extends Element {
    static get template() {
        return html`
        <paper-input label="{{_friendlyName(element.name)}} ({{element.description}})" value="{{element.default}}" name="vol_{{element.name}}" auto-validate="true" required="{{!element.optional}}" error-message="Invalid value"></paper-input>
`;
    }

    static get is() {
        return 'volumetric-requirement-string';
    }

    static get properties() {
        return {
            'element': {
                type: Object,
                notify: true
            }
        }
    }

    _friendlyName(name) {
        return name.substring(name.lastIndexOf('.') + 1, name.length)
    }
}

window.customElements.define(VolumetricRequirementString.is, VolumetricRequirementString);