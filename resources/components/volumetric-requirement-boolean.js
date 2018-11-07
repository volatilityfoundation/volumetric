import {PolymerElement} from '/resources/node_modules/@polymer/polymer/polymer-element.js';
import '/resources/node_modules/@polymer/iron-flex-layout/iron-flex-layout-classes.js';
import '/resources/node_modules/@polymer/iron-ajax/iron-ajax.js';
import '/resources/node_modules/@polymer/iron-form/iron-form.js';
import '/resources/node_modules/@polymer/paper-checkbox/paper-checkbox.js';
import '/resources/node_modules/@polymer/paper-icon-button/paper-icon-button.js';
import '/resources/node_modules/@polymer/paper-input/paper-input.js';
import '/resources/node_modules/@polymer/paper-item/paper-item.js';
import {html} from '../node_modules/@polymer/polymer/lib/utils/html-tag.js';

class VolumetricRequirementBoolean extends PolymerElement {
    static get template() {
        return html`
        <paper-checkbox label="{{_friendlyName(element.name)}} ({{element.description}})" checked\$="{{element.default}}" name="vol_{{element.name}}" required="{{!element.optional}}" error-message="Invalid value">{{_friendlyName(element.name)}}
            ({{element.description}})
        </paper-checkbox>
`;
    }

    static get is() {
        return 'volumetric-requirement-boolean';
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

window.customElements.define(VolumetricRequirementBoolean.is, VolumetricRequirementBoolean);
