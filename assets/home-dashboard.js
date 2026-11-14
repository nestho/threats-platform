export function filterActivityEvents(events, category = "all") {
  return category === "all" ? events : events.filter((event) => event.category === category);
}
