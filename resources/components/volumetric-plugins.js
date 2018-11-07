import {Element} from '/resources/node_modules/@polymer/polymer/polymer-element.js';
import '/resources/node_modules/paper-collapse-item/paper-collapse-item.js';
import '/resources/node_modules/@polymer/paper-listbox/paper-listbox.js';
import '/resources/node_modules/@polymer/paper-item/paper-item.js';
import '/resources/node_modules/@polymer/paper-card/paper-card.js';
import '/resources/node_modules/@polymer/iron-ajax/iron-ajax.js';
import {html} from '../node_modules/@polymer/polymer/lib/utils/html-tag.js';

class VolumetricPlugins extends Element {
    static get template() {
        return html`
    <style>
      :host {
          display: block;

          padding: 10px;
      }

      paper-collapse-item {
          text-transform: capitalize;
      }

      paper-card {
          width: 100%;
      }
    </style>

        <iron-ajax id="listPlugins" url="/api/plugins/list" last-response="{{items}}" auto=""></iron-ajax>


        <paper-card heading="Available Plugins">
            <template is="dom-repeat" items="[[_top_level(items)]]">
                <paper-collapse-item header="[[item]]">
                    <paper-listbox>
                        <template is="dom-repeat" items="[[_filtered(items, item)]]" as="subitem">
                            <paper-item value="{{subitem}}" on-tap="_select_plugin">
                                <paper-item-body two-line="">
                                    <div>{{_friendly_name(subitem)}}</div>
                                    <div secondary="">{{_description(subitem)}}</div>
                                </paper-item-body>
                            </paper-item>
                        </template>
                    </paper-listbox>
                </paper-collapse-item>
            </template>
        </paper-card>
`;
    }

    static get is() {
        return 'volumetric-plugins';
    }

    static get properties() {
        return {
            'page': {
                type: String,
                observer: '_refresh',
                notify: true
            },
            'plugin': {
                type: String,
                notify: true
            }
        }
    }

    _description(item) {
        return item[1];
    }

    _friendly_name(item) {
        return item[0].substring(item[0].lastIndexOf(".") + 1, item[0].length);
    }

    _filtered(items, item) {
        let result = [];
        for (let i = 0; i < items.length; i++) {
            if (items[i][0].substring(0, item.length) === item) {
                result.push(items[i]);
            }
        }
        return result;
    }

    _refresh() {
        if (this.page == 'plugins') {
            this.$.listPlugins.generateRequest();
        }
    }

    _select_plugin(e) {
        this.plugin = e.target.value;
        this.page = 'config';
        console.log("Plugin selected: " + this.plugin);
    }

    _toggle_info(e) {
        let collapseElem = this.shadowRoot.querySelector('#collapse' + e.currentTarget.dataset.index);
        collapseElem.toggle();
    }

    _top_level(items) {
        items.sort();
        let result = [];
        if (items !== null) {
            for (let i = 0; i < items.length; i++) {
                let top_level = items[i][0].substring(0, items[i][0].indexOf("."));
                if (result[result.length - 1] != top_level) {
                    result.push(top_level);
                }
            }
        }
        return result;
    }
}

window.customElements.define(VolumetricPlugins.is, VolumetricPlugins);
