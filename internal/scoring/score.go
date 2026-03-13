package scoring

import "github.com/dativo-io/talon/internal/evidence"

type GovernanceScore struct {
	AgentID string  `json:"agent_id"`
	Score   float64 `json:"score"`
	Level   string  `json:"level"` // low | medium | high
}

func Compute(list []evidence.Evidence, agentID string) GovernanceScore {
	total := 0
	denied := 0
	piiDetected := 0
	evidenceComplete := 0
	for i := range list {
		ev := list[i]
		if ev.AgentID != agentID {
			continue
		}
		total++
		if !ev.PolicyDecision.Allowed {
			denied++
		}
		if len(ev.Classification.PIIDetected) > 0 {
			piiDetected++
		}
		if ev.AuditTrail.InputHash != "" && ev.Signature != "" {
			evidenceComplete++
		}
	}
	if total == 0 {
		return GovernanceScore{AgentID: agentID, Score: 0, Level: "low"}
	}
	complianceRate := 1.0 - (float64(denied) / float64(total))
	evidenceRate := float64(evidenceComplete) / float64(total)
	piiHandlingRate := 1.0
	if piiDetected > 0 {
		piiHandlingRate = 0.8 // conservative proxy until explicit output-redaction checks are added
	}
	score := (complianceRate * 50) + (evidenceRate * 35) + (piiHandlingRate * 15)
	level := "low"
	if score >= 85 {
		level = "high"
	} else if score >= 60 {
		level = "medium"
	}
	return GovernanceScore{AgentID: agentID, Score: score, Level: level}
}
