package store

import "testing"

func TestRepairEndpointIDs(t *testing.T) {
	d := &Data{Seq: map[string]int{}, Endpoints: []*Endpoint{{ID: "EP1", Host: "A"}, {ID: "EP2", Host: "B"}, {ID: "EP1", Host: "C"}},
		AgentCreds: map[string]*AgentCred{"EP1": {Host: "C", Hash: "h"}}}
	if n := RepairEndpointIDs(d); n != 1 {
		t.Fatalf("应修复 1 个重复编号，实际 %d", n)
	}
	c := d.Endpoints[2]
	if c.ID == "EP1" || c.ID == "EP2" || d.AgentCreds[c.ID] == nil || d.AgentCreds["EP1"] != nil {
		t.Fatalf("重复终端应重新编号并迁移凭据：%s %v", c.ID, d.AgentCreds)
	}
	if id := NewEndpointID(d); id == "EP1" || id == "EP2" || id == c.ID {
		t.Fatalf("新编号不应与已有终端重复：%s", id)
	}
}
