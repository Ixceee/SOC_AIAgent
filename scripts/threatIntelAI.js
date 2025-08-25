const axios = require('axios');

module.exports = async ({ network, app, endpoint }) => {
  const iocs = {
    ips: [...new Set([network?.srcip, network?.dstip].filter(Boolean))],
    domains: [app?.hostname].filter(Boolean),
    hashes: [endpoint?.process_hash].filter(Boolean)
  };

  try {
    const response = await axios.post('https://api.openai.com/v1/chat/completions', {
      model: "gpt-4-turbo-preview",
      messages: [
        {
          role: "system",
          content: "Correlate IOCs with threat intel and return JSON: {verdict: string, matched_iocs: string[]}"
        },
        {
          role: "user",
          content: JSON.stringify(iocs)
        }
      ],
      response_format: { type: "json_object" }
    }, {
      headers: {
        "Authorization": `Bearer ${process.env.OPENAI_API_KEY}`,
        "Content-Type": "application/json"
      },
      timeout: 25000
    });

    return response.data.choices[0].message.content;
  } catch (error) {
    console.error('Threat intel failed:', error);
    return {
      verdict: "inconclusive",
      error: error.message
    };
  }
};