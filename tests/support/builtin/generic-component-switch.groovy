// Stand-in for Hubitat's built-in Generic Component Switch: forwards commands
// to the parent and applies the events the parent sends with parse(List).
metadata {
    definition(name: "Generic Component Switch", namespace: "hubitat", author: "Hubitat") {
        capability "Switch"
        capability "Refresh"
    }
}

void parse(List<Map> events) { events.each { sendEvent(it) } }
void on() { parent.componentOn(device) }
void off() { parent.componentOff(device) }
void refresh() { parent.componentRefresh(device) }
