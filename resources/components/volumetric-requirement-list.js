/*
 * This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
 * which is available at https://www.volatilityfoundation.org/license/vsl_v1.0
 *
 */
import {PolymerElement} from '/resources/node_modules/@polymer/polymer/polymer-element.js';
import '/resources/node_modules/@polymer/iron-flex-layout/iron-flex-layout-classes.js';
import '/resources/node_modules/@polymer/iron-ajax/iron-ajax.js';
import '/resources/node_modules/@polymer/iron-form/iron-form.js';
import '/resources/node_modules/@polymer/paper-card/paper-card.js';
import '/resources/node_modules/@polymer/paper-listbox/paper-listbox.js';
import '/resources/node_modules/@polymer/paper-icon-button/paper-icon-button.js';
import '/resources/node_modules/@polymer/paper-input/paper-input.js';
import '/resources/node_modules/@polymer/paper-item/paper-item.js';
import {html} from '../node_modules/@polymer/polymer/lib/utils/html-tag.js';

class VolumetricRequirementList extends PolymerElement {
    static get template() {
        return html`
        <style is="custom-style" include="iron-flex iron-flex-alignment">
            .fullwidth {
                width: 100%;
            }
        </style>
        <div class="layout horizontal fullwidth">
            <div class="layout vertical">
                <paper-icon-button icon="add" on-tap="btn_add"></paper-icon-button>
                <paper-icon-button icon="remove" on-tap="btn_remove"></paper-icon-button>
            </div>
            <div class="fullwidth layout vertical">
                <div>{{_friendlyName(element.name)}} ({{element.description}})</div>
                <paper-listbox id="listbox" class="fullwidth">
                    <template is="dom-repeat" items="{{elements}}">
                        <paper-item>
                            <!-- TODO: Ideally this would be string/integer/boolean requirements -->
                            <paper-input label="{{_friendlyName(element.name)}}" value="{{item}}" name="vol_{{element.name}}" auto-validate="true" class="fullwidth" required="{{!element.optional}}" error-message="Invalid value"></paper-input>
                        </paper-item>
                    </template>
                </paper-listbox>
            </div>
        </div>
`;
    }

    static get is() {
        return 'volumetric-requirement-list';
    }

    static get properties() {
        return {
            'element': {
                type: Object,
                notify: true
            },
            'elements': {
                type: Object,
                notify: true,
                value: function() {
                    return [];
                }
            }
        }
    }

    btn_add() {
        this.push("elements", "");
    }

    btn_remove() {
        var index = this.$.listbox.selected;
        this.elements.splice(index, 1);
        this.notifySplices('elements', {index: index, removed: "", addedCount: 0, object: this.elements});
    }

    clone(obj) {
        return JSON.parse(JSON.stringify(obj));
    }

    _friendlyName(name) {
        return name.substring(name.lastIndexOf('.') + 1, name.length)
    }
}

window.customElements.define(VolumetricRequirementList.is, VolumetricRequirementList);
