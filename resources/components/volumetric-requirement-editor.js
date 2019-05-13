import {PolymerElement} from '/resources/node_modules/@polymer/polymer/polymer-element.js';
import '/resources/node_modules/@polymer/iron-flex-layout/iron-flex-layout-classes.js';
import '/resources/node_modules/@polymer/iron-ajax/iron-ajax.js';
import '/resources/node_modules/@polymer/iron-form/iron-form.js';
import '/resources/node_modules/@polymer/paper-listbox/paper-listbox.js';
import '/resources/node_modules/@polymer/paper-item/paper-item.js';
import '/resources/node_modules/@polymer/paper-icon-button/paper-icon-button.js';
import '/resources/node_modules/@polymer/paper-input/paper-input.js';
import '/resources/components/volumetric-requirement-boolean.js';
import '/resources/components/volumetric-requirement-string.js';
import '/resources/components/volumetric-requirement-uri.js';
import '/resources/components/volumetric-requirement-list.js';
import {html} from '../node_modules/@polymer/polymer/lib/utils/html-tag.js';

class VolumetricRequirementEditor extends PolymerElement {
    static get template() {
        return html`
        <style is="custom-style" include="iron-flex iron-flex-alignment">
            :host {
                display: block;

                padding: 10px;
            }

            paper-card {
                width: 100%;
            }
        </style>

        <template is="dom-repeat" items="{{requirements}}">
            <template is="dom-if" if="{{is_type(item.type, 'IntRequirement')}}">
                <volumetric-requirement-string element="{{item}}"></volumetric-requirement-string>
            </template>
            <template is="dom-if" if="{{is_type(item.type, 'BooleanRequirement')}}">
                <volumetric-requirement-boolean element="{{item}}"></volumetric-requirement-boolean>
            </template>
            <template is="dom-if" if="{{is_type(item.type, 'StringRequirement')}}">
                <volumetric-requirement-string element="{{item}}"></volumetric-requirement-string>
            </template>
            <template is="dom-if" if="{{is_type(item.type, 'URIRequirement')}}">
                <volumetric-requirement-uri element="{{item}}"></volumetric-requirement-uri>
            </template>
            <template is="dom-if" if="{{is_type(item.type, 'ListRequirement')}}">
                <volumetric-requirement-list element="{{item}}"></volumetric-requirement-list>
            </template>
        </template>
`;
    }

    static get is() {
        return 'volumetric-requirement-editor';
    }

    static get properties() {
        return {
            'element': {
                type: Object,
                notify: true
            },
            'requirements': {
                type: Object,
                notify: true
            }
        }
    }

    is_type(element, type) {
        return (element == type);
    }
}

window.customElements.define(VolumetricRequirementEditor.is, VolumetricRequirementEditor);
