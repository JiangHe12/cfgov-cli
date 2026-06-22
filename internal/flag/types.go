package flag

type FeatureFlag struct {
	Key            string        `json:"key"`
	Enabled        bool          `json:"enabled"`
	Description    string        `json:"description,omitempty"`
	DefaultVariant string        `json:"defaultVariant,omitempty"`
	Variants       []Variant     `json:"variants,omitempty"`
	Rules          []RolloutRule `json:"rules,omitempty"`
}

type Variant struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type RolloutRule struct {
	Variant        string `json:"variant"`
	RolloutPercent int    `json:"rolloutPercent"`
	Segment        string `json:"segment,omitempty"`
}
