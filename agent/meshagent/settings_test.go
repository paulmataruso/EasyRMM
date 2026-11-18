package meshagent

import "testing"

func TestWithServiceName(t *testing.T) {
	for in, want := range map[string]string{
		"":                                      "meshServiceName=X\n",
		"MeshID=0x1\n":                          "MeshID=0x1\nmeshServiceName=X\n",
		"MeshID=0x1":                            "MeshID=0x1\nmeshServiceName=X\n",
		"MeshID=0x1\r\nMeshServiceName=Y\r\n":   "MeshID=0x1\r\nmeshServiceName=X\r\n",
		"A=1\r\nmeshservicename = Y\r\nB=2\r\n": "A=1\r\nB=2\r\nmeshServiceName=X\r\n",
	} {
		if got := string(WithServiceName([]byte(in), "X")); got != want {
			t.Errorf("WithServiceName(%q) = %q, want %q", in, got, want)
		}
	}
}
