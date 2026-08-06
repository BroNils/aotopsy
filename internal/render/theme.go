package render

// Theme holds colors for callgraph rendering.
type Theme struct {
	Background string
	NodeFill   string
	NodeBorder string
	TextColor  string

	// Edge colors by provenance category.
	EdgeTHR        string // THR.* runtime entry calls
	EdgePP         string // PP[n] pool-loaded calls
	EdgeDispatch   string // dispatch_table (virtual calls)
	EdgeObject     string // object_field (vtable/closure)
	EdgeDirect     string // BL direct calls
	EdgeUnresolved string // unannotated BLR

	// Node accents.
	StubFill     string // runtime stubs (sub_xxx)
	ExternalText string // external / unresolved targets

	// Cluster styling.
	ClusterBorder string // subgraph cluster border
	ClusterLabel  string // subgraph cluster label text
}

// NASA is the NASA/Bauhaus theme: geometric, monochrome, sparse color.
var NASA = Theme{
	Background: "#F5F5F5",
	NodeFill:   "white",
	NodeBorder: "#1A1A1A",
	TextColor:  "#1A1A1A",

	EdgeTHR:        "#0B3D91", // NASA blue
	EdgePP:         "#00695C", // teal
	EdgeDispatch:   "#9E9E9E", // gray
	EdgeObject:     "#E65100", // deep orange
	EdgeDirect:     "#424242", // dark gray
	EdgeUnresolved: "#FC3D21", // NASA red

	StubFill:     "#ECEFF1", // blue-gray 50
	ExternalText: "#9E9E9E",

	ClusterBorder: "#BDBDBD",
	ClusterLabel:  "#757575",
}
